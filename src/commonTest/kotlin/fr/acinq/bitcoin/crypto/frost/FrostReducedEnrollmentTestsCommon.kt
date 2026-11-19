@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.*

/**
 * Reduced (version 2) FROST enrollment through the bitcoin-kmp wrapper.
 *
 * The arithmetic is covered by the secp256k1 module's suite and by the binding tests and vectors in secp256k1-kmp.
 * What is exercised here is what this layer adds: routing by identifier instead of by position, the check that
 * exactly the expected senders are present, the attribution of a fault to an identifier, and the encoding of the
 * point at infinity among VSS commitments.
 */
class FrostReducedEnrollmentTestsCommon {
    private val thresholdSecretKey = PrivateKey.fromHex("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")

    /** Deterministic per-helper randomness, so that a failure reproduces. Real callers must use fresh randomness. */
    private fun sessionRandom(helper: Int): ByteVector32 = ByteVector32(ByteArray(32) { (it + 1 + 31 * helper).toByte() })

    private fun sessionId(run: Int): ByteVector32 = ByteVector32(ByteArray(32) { (0xa0 + run).toByte() })

    private class Enrollment(val secretShare: PrivateKey, val publicShare: PublicKey, val toTarget: Map<UInt, ReducedEnrollmentMessage>)

    private fun round1(km: KeyMaterial, helperIds: List<UInt>, newId: UInt, sid: ByteVector32): Map<UInt, ReducedEnrollmentShares> =
        helperIds.associateWith { myId ->
            FrostReducedEnrollment.generateShares(sessionRandom(myId.toInt()), km.secretShares[myId.toInt()], km.thresholdPublicKey, helperIds, myId, newId, km.nParticipants, km.threshold, sid).right!!
        }

    /** What helper [myId] receives in round 1.1: one message from every helper with a smaller identifier. */
    private fun inbox(rows: Map<UInt, ReducedEnrollmentShares>, myId: UInt): Map<UInt, ReducedEnrollmentMessage> =
        rows.filterKeys { it < myId }.mapValues { (_, row) -> row.messageFor(myId) }

    private fun runEnrollment(km: KeyMaterial, helperIds: List<UInt>, newId: UInt, sid: ByteVector32): Enrollment {
        val n = km.nParticipants
        val t = km.threshold
        val rows = round1(km, helperIds, newId, sid)
        val toTarget = helperIds.associateWith { myId ->
            val result = FrostReducedEnrollment.aggregateShares(rows.getValue(myId).kept, inbox(rows, myId), km.thresholdPublicKey, helperIds, myId, newId, n, t, sid)
            assertIs<ReducedShareAggregation.Aggregated>(result.right, "share aggregation faulted for helper $myId").message
        }
        val publicShare = FrostEnrollment.derivePublicShare(helperIds.map { km.publicShares[it.toInt()] }, helperIds, newId, n, t).right!!
        val secretShare = FrostReducedEnrollment.generateSecretShare(toTarget, km.thresholdPublicKey, helperIds, newId, n, t, sid, publicShare).right!!
        return Enrollment(secretShare, publicShare, toTarget)
    }

    @Test
    fun enrollNewParticipant() {
        for (n in 3..5) {
            for (t in 2..n) {
                for (u in t..n) {
                    val km = Frost.trustedDealerKeygen(thresholdSecretKey, n, t)
                    // Listed out of order, so that an implementation routing by position rather than identifier fails.
                    val helperIds = (0 until u).map { it.toUInt() }.reversed()
                    val e = runEnrollment(km, helperIds, n.toUInt(), sessionId(n * 100 + t * 10 + u))
                    assertEquals(e.publicShare, e.secretShare.publicKey(), "n=$n t=$t u=$u")
                    val extended = KeyMaterial(km.thresholdPublicKey, km.secretShares + e.secretShare, km.publicShares + e.publicShare, t)
                    assertTrue(extended.isValid(), "n=$n t=$t u=$u")
                }
            }
        }
    }

    @Test
    fun repairReproducesTheExistingShare() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        val e = runEnrollment(km, listOf(3u, 0u, 2u), 4u, sessionId(1))
        assertEquals(km.secretShares[4], e.secretShare)
        assertEquals(km.publicShares[4], e.publicShare)
    }

    @Test
    fun sharesAreRoutedOnlyToLargerIdentifiers() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        val helperIds = listOf(4u, 1u, 3u)
        val rows = round1(km, helperIds, 5u, sessionId(2))
        assertEquals(setOf(3u, 4u), rows.getValue(1u).outgoing.keys)
        assertEquals(setOf(4u), rows.getValue(3u).outgoing.keys)
        assertEquals(emptySet(), rows.getValue(4u).outgoing.keys)
        // u(u-1)/2 messages in all, against the full protocol's u(u-1).
        assertEquals(3, rows.values.sumOf { it.outgoing.size })
        // Every helper computed the same hash, and it is the one paramsHash gives for the same run.
        val expected = FrostReducedEnrollment.paramsHash(km.thresholdPublicKey, helperIds, 5u, 5, 3, sessionId(2)).right!!
        rows.values.forEach { assertEquals(expected, it.paramsHash) }
    }

    @Test
    fun paramsHashBindsTheSessionAndDiffersFromTheFullProtocol() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val base = FrostReducedEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 4u, 4, 2, sessionId(0)).right!!
        assertEquals(base, FrostReducedEnrollment.paramsHash(km.thresholdPublicKey, listOf(1u, 0u), 4u, 4, 2, sessionId(0)).right!!)
        assertNotEquals(base, FrostReducedEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 4u, 4, 2, sessionId(1)).right!!)
        assertNotEquals(base, FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 4u, 4, 2).right!!)
    }

    @Test
    fun faultIsReportedByIdentifierNotIndex() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        val helperIds = listOf(4u, 1u, 3u)
        val newId = 5u
        val rows = round1(km, helperIds, newId, sessionId(3))
        // Helper 1 ran round 1.1 for a different session, so the hash it sends helper 4 is not this run's.
        val replayed = round1(km, helperIds, newId, sessionId(4)).getValue(1u).messageFor(4u)
        val received = inbox(rows, 4u) + (1u to replayed)
        val result = FrostReducedEnrollment.aggregateShares(rows.getValue(4u).kept, received, km.thresholdPublicKey, helperIds, 4u, newId, 5, 3, sessionId(3))
        assertEquals(ReducedShareAggregation.HelperAtFault(1u), result.right)
    }

    @Test
    fun exactlyTheExpectedSendersArePresent() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        val helperIds = listOf(0u, 2u, 3u)
        val sid = sessionId(5)
        val rows = round1(km, helperIds, 5u, sid)
        val kept = rows.getValue(2u).kept
        fun aggregate(received: Map<UInt, ReducedEnrollmentMessage>) =
            FrostReducedEnrollment.aggregateShares(kept, received, km.thresholdPublicKey, helperIds, 2u, 5u, 5, 3, sid)
        assertIs<ReducedShareAggregation.Aggregated>(aggregate(inbox(rows, 2u)).right)
        // A missing message is the caller's routing mistake, not helper 0 at fault.
        assertTrue(aggregate(emptyMap()).isLeft)
        // So is a message from a larger identifier, which the protocol never sends.
        assertTrue(aggregate(inbox(rows, 2u) + (3u to rows.getValue(0u).messageFor(3u))).isLeft)

        val e = runEnrollment(km, helperIds, 5u, sid)
        assertTrue(FrostReducedEnrollment.generateSecretShare(e.toTarget - 3u, km.thresholdPublicKey, helperIds, 5u, 5, 3, sid, e.publicShare).isLeft)
    }

    @Test
    fun roundTwoChecksAreLoadBearing() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val helperIds = listOf(0u, 1u)
        val sid = sessionId(6)
        val e = runEnrollment(km, helperIds, 4u, sid)
        // A wrong expected public share is caught.
        assertTrue(FrostReducedEnrollment.generateSecretShare(e.toTarget, km.thresholdPublicKey, helperIds, 4u, 4, 2, sid, km.publicShares[0]).isLeft)
        // So is a target that verifies under another session than the one the helpers ran.
        assertTrue(FrostReducedEnrollment.generateSecretShare(e.toTarget, km.thresholdPublicKey, helperIds, 4u, 4, 2, sessionId(7), e.publicShare).isLeft)
        // And a helper message carrying another hash.
        val tampered = e.toTarget + (1u to e.toTarget.getValue(1u).copy(paramsHash = ByteVector32(ByteArray(32) { 0x11 })))
        assertTrue(FrostReducedEnrollment.generateSecretShare(tampered, km.thresholdPublicKey, helperIds, 4u, 4, 2, sid, e.publicShare).isLeft)
    }

    @Test
    fun publicShareFromCommitments() {
        // A degree-1 polynomial f(x) = a0 + a1.x whose commitments are known, unlike a trusted dealer's.
        val a0 = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101")
        val a1 = PrivateKey.fromHex("0202020202020202020202020202020202020202020202020202020202020202")
        val commitments = listOf(a0.publicKey(), a1.publicKey())
        val n = 4
        val publicShares = (0 until n).map { FrostReducedEnrollment.derivePublicShareFromCommitments(a0.publicKey(), commitments, it.toUInt(), n).right!! }
        // The shares the commitments describe form a valid group under a0.G. There are no secret shares to build a
        // KeyMaterial with, so this is the check KeyMaterial.isValid makes, made directly.
        assertTrue(Secp256k1.frostThresholdInfoValidate(a0.publicKey().value.toByteArray(), publicShares.map { it.value.toByteArray() }.toTypedArray(), 2))
        // And extending it agrees with interpolation from any two existing public shares.
        val fromCommitments = FrostReducedEnrollment.derivePublicShareFromCommitments(a0.publicKey(), commitments, n.toUInt(), n).right!!
        val fromShares = FrostEnrollment.derivePublicShare(listOf(publicShares[1], publicShares[3]), listOf(1u, 3u), n.toUInt(), n, 2).right!!
        assertEquals(fromShares, fromCommitments)
        // The first commitment must be the threshold public key.
        assertTrue(FrostReducedEnrollment.derivePublicShareFromCommitments(a1.publicKey(), commitments, n.toUInt(), n).isLeft)
    }

    @Test
    fun nullCommitmentIsThePointAtInfinity() {
        // With a1 = 0 the polynomial is constant, so every participant's public share is the threshold public key.
        val a0 = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101")
        val share = FrostReducedEnrollment.derivePublicShareFromCommitments(a0.publicKey(), listOf(a0.publicKey(), null), 2u, 4).right!!
        assertEquals(a0.publicKey(), share)
    }
}
