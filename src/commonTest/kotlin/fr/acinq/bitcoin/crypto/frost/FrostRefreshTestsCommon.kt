@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.dkg.chill.ChillDKG
import fr.acinq.secp256k1.ChilldkgFault
import kotlin.test.*

/**
 * FROST share refresh through the bitcoin-kmp wrapper, and the one composition that makes it useful: re-enrollment.
 *
 * The protocol's properties are carried by the zkp module's own suite, and the bytes by the binding tests and
 * vectors in secp256k1-kmp. What is exercised here is what this layer adds -- messages keyed by identifier, faults
 * attributed to an identifier, a missing or extra entry as the caller's error -- and the round trip a group actually
 * needs: refresh without a participant, repair it under the new generation with [FrostReducedEnrollment], and sign
 * with it in the signer set.
 */
class FrostRefreshTestsCommon {
    private val thresholdSecretKey = PrivateKey.fromHex("5ea1ed00000000000000000000000000000000000000000000000000000000a1")

    /** Deterministic randomness, so a failure reproduces. Real callers must use fresh randomness. */
    private fun rand(tag: Int, i: Int): ByteVector32 = ByteVector32(ByteArray(32) { (tag * 31 + i * 7 + it + 1).toByte() })

    private class Group(val km: KeyMaterial, val hostSecretKeys: List<PrivateKey>) {
        val hostPublicKeys: List<PublicKey> = hostSecretKeys.map { ChillDKG.hostPublicKey(it) }
    }

    private fun deal(n: Int, t: Int): Group =
        Group(Frost.trustedDealerKeygen(thresholdSecretKey, n, t), List(n) { PrivateKey(rand(9, it)) })

    private class Refreshed(
        val params: FrostRefreshParams,
        val coordinatorMessage: ByteVector,
        val newSecretShares: Map<UInt, PrivateKey>,
        val newPublicShares: List<PublicKey>,
        val signatures: Map<UInt, ByteVector64>,
    )

    private fun refresh(g: Group, recipients: List<UInt>, generation: UInt = 0u, run: Int = 0): Refreshed {
        val params = FrostRefresh.params(g.km.thresholdPublicKey, g.hostPublicKeys, g.km.publicShares, g.km.threshold, generation, recipients, rand(1, run)).right!!
        val round1 = recipients.associateWith { id -> FrostRefresh.participantStep1(g.hostSecretKeys[id.toInt()], params, id, rand(2, run * 10 + id.toInt())).right!! }
        val coordinated = FrostRefresh.coordinatorStep1(round1, params)
        assertTrue(coordinated.fault.isOk, "$coordinated")
        val cmsg1 = coordinated.message!!
        val round2 = recipients.associateWith { id ->
            FrostRefresh.participantStep2(g.hostSecretKeys[id.toInt()], g.km.secretShares[id.toInt()], params, id, cmsg1, rand(3, run * 10 + id.toInt()))
        }
        round2.values.forEach { assertTrue(it.fault.isOk, "$it") }
        val table = round2.values.first().newPublicShares!!
        round2.values.forEach { assertEquals(table, it.newPublicShares) }
        return Refreshed(params, cmsg1, round2.mapValues { it.value.newSecretShare!! }, table, round2.mapValues { it.value.certEqSignature!! })
    }

    /** Signs with [signers] and checks the signature under the group's unchanged key. */
    private fun assertSigns(km: KeyMaterial, signers: List<UInt>) {
        val msg = ByteVector32(ByteArray(32) { 0x5a })
        val nonces = signers.map { id ->
            Frost.generateNonce(rand(4, id.toInt()), km.secretShares[id.toInt()], km.publicShares[id.toInt()], km.tweakCache().tweakedPublicKey, msg, null)
        }
        val publicNonces = nonces.map { it.second }
        val partials = signers.mapIndexed { i, id -> Frost.sign(km.secretShares[id.toInt()], nonces[i].first, id, msg, signers, km, publicNonces).right!! }
        val sig = Frost.aggregatePartialSignatures(partials, msg, signers, km, publicNonces).right
        assertNotNull(sig, "signers $signers")
        assertTrue(Crypto.verifySignatureSchnorr(msg, sig, km.tweakCache().tweakedPublicKey), "signers $signers")
    }

    @Test
    fun refreshKeepsTheKeyAndMovesEveryShare() {
        for (n in 2..5) {
            for (t in 2..n) {
                val g = deal(n, t)
                val all = (0 until n).map { it.toUInt() }
                val r = refresh(g, all, run = n * 10 + t)
                val newKm = KeyMaterial(g.km.thresholdPublicKey, all.map { r.newSecretShares.getValue(it) }, r.newPublicShares, t)
                assertTrue(newKm.isValid(), "n=$n t=$t")
                all.forEach { id ->
                    assertNotEquals(g.km.secretShares[id.toInt()], r.newSecretShares[id], "n=$n t=$t")
                    assertEquals(r.newPublicShares[id.toInt()], r.newSecretShares.getValue(id).publicKey())
                }
                assertSigns(newKm, all.take(t))
            }
        }
    }

    /**
     * The whole of re-enrollment, below the app: participant 2 is withheld from a refresh, then repaired at its own
     * identifier under the new generation by t recipients, checked against the new table's entry for it -- and
     * signs. Its old share, which its old device still has, is not that share.
     */
    @Test
    fun withheldThenRepairedThenSigns() {
        val g = deal(4, 3)
        val withheld = 2u
        val r = refresh(g, listOf(0u, 1u, 3u), run = 1)
        assertEquals(listOf(withheld), r.params.withheldIds)
        assertNull(r.newSecretShares[withheld])

        // Repair: t helpers of the new generation, the expected public share from the (authenticated) new table.
        val helpers = listOf(0u, 1u, 3u)
        val sid = rand(5, 0)
        val rows = helpers.associateWith { id ->
            FrostReducedEnrollment.generateShares(rand(6, id.toInt()), r.newSecretShares.getValue(id), g.km.thresholdPublicKey, helpers, id, withheld, 4, 3, sid).right!!
        }
        val toTarget = helpers.associateWith { id ->
            val inbox = rows.filterKeys { it < id }.mapValues { (_, row) -> row.messageFor(id) }
            val agg = FrostReducedEnrollment.aggregateShares(rows.getValue(id).kept, inbox, g.km.thresholdPublicKey, helpers, id, withheld, 4, 3, sid).right!!
            assertIs<ReducedShareAggregation.Aggregated>(agg).message
        }
        val repaired = FrostReducedEnrollment.generateSecretShare(toTarget, g.km.thresholdPublicKey, helpers, withheld, 4, 3, sid, r.newPublicShares[withheld.toInt()]).right!!

        assertEquals(r.newPublicShares[withheld.toInt()], repaired.publicKey())
        assertNotEquals(g.km.secretShares[withheld.toInt()], repaired, "the repair must not hand back the share the old device has")

        val shares = (0u..3u).map { if (it == withheld) repaired else r.newSecretShares.getValue(it) }
        val newKm = KeyMaterial(g.km.thresholdPublicKey, shares, r.newPublicShares, 3)
        assertTrue(newKm.isValid())
        assertSigns(newKm, listOf(0u, 2u, 3u))

        // The old share at the same identifier is on the old polynomial: against the new table it is a wrong share.
        val stale = KeyMaterial(g.km.thresholdPublicKey, shares.mapIndexed { i, s -> if (i == 2) g.km.secretShares[2] else s }, r.newPublicShares, 3)
        assertNotEquals(r.newPublicShares[2], stale.secretShares[2].publicKey())
    }

    @Test
    fun certificateRecoveryAndPublicTable() {
        val g = deal(4, 2)
        val r = refresh(g, listOf(0u, 2u, 3u), generation = 3u, run = 2)
        assertEquals(3u, r.params.generation)
        val cert = FrostRefresh.coordinatorFinalize(r.params, r.coordinatorMessage, r.signatures)
        assertTrue(cert.fault.isOk)
        val recovery = FrostRefresh.participantFinalize(r.params, r.coordinatorMessage, cert.output!!).output!!

        listOf(0u, 2u, 3u).forEach { id ->
            val rec = FrostRefresh.participantRecover(g.hostSecretKeys[id.toInt()], g.km.secretShares[id.toInt()], recovery)
            assertTrue(rec.fault.isOk)
            assertEquals(id, rec.participantId)
            assertEquals(r.newSecretShares[id], rec.newSecretShare)
            assertEquals(r.newPublicShares, rec.newPublicShares)
        }
        assertEquals(ChilldkgFault.INVALID_INPUT, FrostRefresh.participantRecover(g.hostSecretKeys[1], g.km.secretShares[1], recovery).fault.code)

        val public = FrostRefresh.publicRecover(recovery)
        assertTrue(public.fault.isOk)
        assertEquals(r.params, public.params)
        assertEquals(r.newPublicShares, public.newPublicShares)
    }

    /** Chained: the table and shares of one refresh are the inputs of the next. */
    @Test
    fun refreshesCompose() {
        val g = deal(3, 2)
        val first = refresh(g, listOf(0u, 1u, 2u), run = 3)
        val g1 = Group(KeyMaterial(g.km.thresholdPublicKey, (0u..2u).map { first.newSecretShares.getValue(it) }, first.newPublicShares, 2), g.hostSecretKeys)
        val second = refresh(g1, listOf(0u, 1u, 2u), generation = 1u, run = 4)
        val g2 = KeyMaterial(g.km.thresholdPublicKey, (0u..2u).map { second.newSecretShares.getValue(it) }, second.newPublicShares, 2)
        assertTrue(g2.isValid())
        assertSigns(g2, listOf(1u, 2u))
        assertNotEquals(FrostRefresh.paramsHash(first.params), FrostRefresh.paramsHash(second.params))
    }

    /** A fault names the identifier, never the position in the recipient list. */
    @Test
    fun faultIsAttributedToAnIdentifier() {
        val g = deal(4, 2)
        val r = refresh(g, listOf(0u, 2u, 3u), run = 5)
        val bad = r.signatures.mapValues { (id, sig) -> if (id == 3u) ByteVector64(sig.toByteArray().also { it[5] = (it[5].toInt() xor 1).toByte() }) else sig }
        val result = FrostRefresh.coordinatorFinalize(r.params, r.coordinatorMessage, bad)
        assertEquals(ChilldkgFault.FAULTY_PARTICIPANT, result.fault.code)
        // Recipient 3 sits at position 2 in the list; the wrapper must say 3.
        assertEquals(3u, result.fault.participantId)
        assertNull(result.output)
    }

    @Test
    fun exactlyTheRecipientsMustBePresent() {
        val g = deal(3, 2)
        val r = refresh(g, listOf(0u, 1u, 2u), run = 6)
        assertFailsWith<IllegalArgumentException> { FrostRefresh.coordinatorFinalize(r.params, r.coordinatorMessage, r.signatures - 1u) }
        assertFailsWith<IllegalArgumentException> { FrostRefresh.coordinatorFinalize(r.params, r.coordinatorMessage, r.signatures + (7u to r.signatures.getValue(0u))) }
        assertFailsWith<IllegalArgumentException> { FrostRefresh.coordinatorStep1(mapOf(0u to ByteVector.empty), r.params) }
        // Not a recipient: refused before any work.
        val withheldParams = FrostRefresh.params(g.km.thresholdPublicKey, g.hostPublicKeys, g.km.publicShares, 2, 0u, listOf(0u, 1u), rand(1, 7)).right!!
        assertTrue(FrostRefresh.participantStep1(g.hostSecretKeys[2], withheldParams, 2u, rand(2, 7)).isLeft)
        // Fewer recipients than the threshold is not a session.
        assertTrue(FrostRefresh.params(g.km.thresholdPublicKey, g.hostPublicKeys, g.km.publicShares, 2, 0u, listOf(0u), rand(1, 8)).isLeft)
    }

    @Test
    fun paramsRoundTripThroughTheirData() {
        val g = deal(3, 2)
        val params = FrostRefresh.params(g.km.thresholdPublicKey, g.hostPublicKeys, g.km.publicShares, 2, 5u, listOf(0u, 2u), rand(1, 9)).right!!
        assertEquals(params, FrostRefreshParams.fromData(params.data))
        assertEquals(listOf(1u), params.withheldIds)
        assertNull(FrostRefreshParams.fromData(ByteVector(ByteArray(3))))
        assertNull(FrostRefreshParams.fromData(params.data.concat(ByteVector(ByteArray(1)))))
    }
}
