@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import kotlin.test.*

/**
 * FROST enrollment through the bitcoin-kmp wrapper.
 *
 * The arithmetic is covered by the secp256k1 module's own suite and by the binding tests in secp256k1-kmp; what is
 * exercised here is what this layer adds: the alignment of the lists across the transposition between rounds 1.1
 * and 1.2, the null-at-own-position convention of the received parameters hashes, and the three-way outcome of
 * round 1.2, where a helper at fault is a value and only invalid arguments are an error.
 */
class FrostEnrollmentTestsCommon {
    private val thresholdSecretKey = PrivateKey.fromHex("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")

    /** Deterministic per-helper randomness, so that a failure reproduces. Real callers must use fresh randomness. */
    private fun sessionRandom(helper: Int): ByteVector32 = ByteVector32(ByteArray(32) { (it + 1 + 31 * helper).toByte() })

    private class Enrollment(val secretShare: PrivateKey, val publicShare: PublicKey, val paramsHash: ByteVector32)

    /**
     * Run all three rounds. [helperIds] are the u helpers; [newId] is the target, equal to n to enroll a new
     * participant and smaller than n to repair an existing one.
     */
    private fun runEnrollment(km: KeyMaterial, helperIds: List<UInt>, newId: UInt): Enrollment {
        val n = km.nParticipants
        val t = km.threshold
        val u = helperIds.size

        // Round 1.1: each helper splits its contribution into one share per helper.
        val round1 = helperIds.map { myId ->
            FrostEnrollment.generateShares(sessionRandom(myId.toInt()), km.secretShares[myId.toInt()], km.thresholdPublicKey, helperIds, myId, newId, n, t).right!!
        }
        round1.forEach { assertEquals(round1[0].paramsHash, it.paramsHash) }

        // Round 1.2: transpose. The helper at position j collects entry j from every helper, and every helper's
        // parameters hash but its own, which is left null because it is recomputed rather than compared.
        val aggregated = helperIds.mapIndexed { j, myId ->
            val shares = List(u) { i -> round1[i].shares[j] }
            val hashes = List<ByteVector32?>(u) { i -> if (i == j) null else round1[i].paramsHash }
            val result = FrostEnrollment.aggregateShares(shares, hashes, km.thresholdPublicKey, helperIds, myId, newId, n, t)
            assertIs<ShareAggregation.Aggregated>(result.right, "share aggregation faulted for helper $myId").share
        }

        // Round 2: the target sums the values and verifies them against the public share it derives itself.
        val helperPublicShares = helperIds.map { km.publicShares[it.toInt()] }
        val publicShare = FrostEnrollment.derivePublicShare(helperPublicShares, helperIds, newId, n, t).right!!
        val secretShare = FrostEnrollment.generateSecretShare(aggregated, km.thresholdPublicKey, helperIds, newId, n, t, round1[0].paramsHash, publicShare).right!!
        return Enrollment(secretShare, publicShare, round1[0].paramsHash)
    }

    @Test
    fun enrollNewParticipant() {
        // Every helper-set size from t to n, since u is what fixes the alignment of both lists of round 1.2.
        for (n in 3..5) {
            for (t in 2..n) {
                for (u in t..n) {
                    val km = Frost.trustedDealerKeygen(thresholdSecretKey, n, t)
                    val helperIds = (0 until u).map { it.toUInt() }
                    val e = runEnrollment(km, helperIds, n.toUInt())
                    // The share the protocol produced is the discrete log of the independently derived public share.
                    assertEquals(e.publicShare, e.secretShare.publicKey(), "n=$n t=$t u=$u")
                    // And the group extended to n+1 participants is consistent with the same threshold public key.
                    val extended = KeyMaterial(km.thresholdPublicKey, km.secretShares + e.secretShare, km.publicShares + e.publicShare, t)
                    assertTrue(extended.isValid(), "n=$n t=$t u=$u")
                    assertEquals(n + 1, extended.nParticipants)
                }
            }
        }
    }

    @Test
    fun repairReproducesTheExistingShare() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        // Repair participant 4 with three helpers that exclude it: the result must be that participant's actual
        // share, which is what makes this a repair rather than a new share.
        val e = runEnrollment(km, listOf(0u, 1u, 2u), 4u)
        assertEquals(km.secretShares[4], e.secretShare)
        assertEquals(km.publicShares[4], e.publicShare)
    }

    @Test
    fun paramsHashIdentifiesTheGroup() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val base = FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 4u, 4, 2).right!!
        // Sorting makes the hash independent of the order the caller lists the helpers in.
        assertEquals(base, FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(1u, 0u), 4u, 4, 2).right!!)
        // It is what every party recomputes, so it must agree with what round 1.1 returns.
        assertEquals(base, FrostEnrollment.generateShares(sessionRandom(0), km.secretShares[0], km.thresholdPublicKey, listOf(0u, 1u), 0u, 4u, 4, 2).right!!.paramsHash)
        // Binding the threshold public key is what makes it identify a group rather than a tuple of numbers.
        val other = Frost.trustedDealerKeygen(PrivateKey.fromHex("d327593fe753f6fde38f29fd2639d44f62054babea21a359a41d651c81f1e01e"), 4, 2)
        assertNotEquals(base, FrostEnrollment.paramsHash(other.thresholdPublicKey, listOf(0u, 1u), 4u, 4, 2).right!!)
        // And it changes with the helper set and with the target.
        assertNotEquals(base, FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 2u), 4u, 4, 2).right!!)
        assertNotEquals(base, FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 3u, 4, 2).right!!)
    }

    @Test
    fun faultIsReportedByIdentifierNotIndex() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        // A helper set where identifiers and positions do not coincide: a wrapper returning the position would
        // report 2 instead of 4 here, and any set like {0, 1, 2} would hide the difference.
        val helperIds = listOf(1u, 3u, 4u)
        val newId = 5u
        val round1 = helperIds.map { myId ->
            FrostEnrollment.generateShares(sessionRandom(myId.toInt()), km.secretShares[myId.toInt()], km.thresholdPublicKey, helperIds, myId, newId, 5, 3).right!!
        }
        // The helper at position 2, whose identifier is 4, sends a parameters hash it did not compute.
        val corrupted = ByteVector32(ByteArray(32) { 0x11 })
        val shares = List(3) { i -> round1[i].shares[0] }
        val hashes = listOf<ByteVector32?>(null, round1[1].paramsHash, corrupted)
        val result = FrostEnrollment.aggregateShares(shares, hashes, km.thresholdPublicKey, helperIds, 1u, newId, 5, 3)
        assertEquals(ShareAggregation.HelperAtFault(4u), result.right)
    }

    @Test
    fun ownParametersHashIsRecomputedNotCompared() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val helperIds = listOf(0u, 1u)
        val round1 = helperIds.map { myId ->
            FrostEnrollment.generateShares(sessionRandom(myId.toInt()), km.secretShares[myId.toInt()], km.thresholdPublicKey, helperIds, myId, 4u, 4, 2).right!!
        }
        val shares = List(2) { i -> round1[i].shares[0] }
        // Supplying the own slot at all is a caller mistake: the value would be ignored, so accepting it would
        // suggest a check that does not happen.
        val withOwnSlot = FrostEnrollment.aggregateShares(shares, listOf(round1[0].paramsHash, round1[1].paramsHash), km.thresholdPublicKey, helperIds, 0u, 4u, 4, 2)
        assertTrue(withOwnSlot.isLeft)
        // And leaving out another helper's slot would be sent down as a zero hash, blaming that helper for the
        // caller's own mistake.
        val missingOther = FrostEnrollment.aggregateShares(shares, listOf(null, null), km.thresholdPublicKey, helperIds, 0u, 4u, 4, 2)
        assertTrue(missingOther.isLeft)
    }

    @Test
    fun roundTwoChecksAreLoadBearing() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val helperIds = listOf(0u, 1u)
        val newId = 4u
        val round1 = helperIds.map { myId ->
            FrostEnrollment.generateShares(sessionRandom(myId.toInt()), km.secretShares[myId.toInt()], km.thresholdPublicKey, helperIds, myId, newId, 4, 2).right!!
        }
        val aggregated = helperIds.mapIndexed { j, myId ->
            val shares = List(2) { i -> round1[i].shares[j] }
            val hashes = List<ByteVector32?>(2) { i -> if (i == j) null else round1[i].paramsHash }
            assertIs<ShareAggregation.Aggregated>(FrostEnrollment.aggregateShares(shares, hashes, km.thresholdPublicKey, helperIds, myId, newId, 4, 2).right).share
        }
        val publicShare = FrostEnrollment.derivePublicShare(helperIds.map { km.publicShares[it.toInt()] }, helperIds, newId, 4, 2).right!!
        val hash = round1[0].paramsHash

        // A wrong expected public share is caught: this is the only check that the helpers contributed correctly.
        assertTrue(FrostEnrollment.generateSecretShare(aggregated, km.thresholdPublicKey, helperIds, newId, 4, 2, hash, km.publicShares[0]).isLeft)
        // So is a parameters hash that does not match the run.
        assertTrue(FrostEnrollment.generateSecretShare(aggregated, km.thresholdPublicKey, helperIds, newId, 4, 2, ByteVector32(ByteArray(32)), publicShare).isLeft)
        // Skipping both checks yields the same share as performing them.
        val checked = FrostEnrollment.generateSecretShare(aggregated, km.thresholdPublicKey, helperIds, newId, 4, 2, hash, publicShare).right!!
        val unchecked = FrostEnrollment.generateSecretShare(aggregated, km.thresholdPublicKey, helperIds, newId, 4, 2, null, null).right!!
        assertEquals(checked, unchecked)
        assertEquals(publicShare, checked.publicKey())
    }

    @Test
    fun invalidParametersAreErrors() {
        val km = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        // Enrollment needs a threshold of at least 2: a 1-of-n share is the key itself.
        assertTrue(FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u), 4u, 4, 1).isLeft)
        // The target must not be one of the helpers.
        assertTrue(FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 1u), 1u, 4, 2).isLeft)
        // Helper identifiers must be distinct.
        assertTrue(FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 0u), 4u, 4, 2).isLeft)
        // And smaller than the number of participants.
        assertTrue(FrostEnrollment.paramsHash(km.thresholdPublicKey, listOf(0u, 4u), 5u, 4, 2).isLeft)
        // The number of helpers must reach the threshold.
        assertTrue(FrostEnrollment.derivePublicShare(listOf(km.publicShares[0]), listOf(0u), 4u, 4, 2).isLeft)
    }
}
