package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class FrostRefreshTestsCommon {
    private val thresholdSecretKey = PrivateKey.fromHex("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")
    private val sessionId = ByteVector32(ByteArray(32) { 0x52 })
    private val ids = { n: Int -> (0 until n).map { it.toUInt() } }
    private val one = PrivateKey(ByteArray(31) + 1.toByte())

    private data class RefreshRun(
        val candidates: List<RefreshCandidate>,
        val dealerShares: List<RefreshShares>,
    )

    private fun seed(dealer: Int): ByteVector32 = ByteVector32(ByteArray(32) { (it + 1 + 31 * dealer).toByte() })

    private fun refresh(km: KeyMaterial, currentEpoch: Long = 0): RefreshRun {
        val participantIds = ids(km.nParticipants)
        val dealerShares = participantIds.map { dealerId ->
            FrostRefresh.generateShares(
                seed(dealerId.toInt()), km.secretShares[dealerId.toInt()], sessionId,
                km.thresholdPublicKey, currentEpoch, currentEpoch + 1, participantIds, dealerId, km.threshold,
            ).right!!
        }
        val candidates = participantIds.map { recipientId ->
            FrostRefresh.generateCandidate(
                km.secretShares[recipientId.toInt()], km.publicShares,
                dealerShares.map { it.evaluations[recipientId.toInt()] },
                dealerShares.map { it.commitments }, recipientId, sessionId, km.thresholdPublicKey,
                currentEpoch, currentEpoch + 1, participantIds, km.threshold,
            ).right!!
        }
        return RefreshRun(candidates, dealerShares)
    }

    private fun sign(km: KeyMaterial, signerIds: List<Int>, salt: Int): Boolean {
        val message = ByteVector32(Crypto.sha256("FROST refresh signature $salt".encodeToByteArray()))
        val cache = km.tweakCache()
        val nonces = signerIds.map { signerId ->
            SecretNonce.generate(
                ByteVector32(Crypto.sha256("FROST refresh nonce $salt/$signerId".encodeToByteArray())),
                km.secretShares[signerId], km.publicShares[signerId], cache.tweakedPublicKey, message, null,
            )
        }
        val aggregate = IndividualNonce.aggregate(nonces.map { it.second }).right!!
        val session = Session.create(
            aggregate, signerIds.map { it.toUInt() }, signerIds.map { km.publicShares[it] },
            km.nParticipants, km.threshold, cache, message,
        )
        val partials = signerIds.mapIndexed { index, signerId ->
            session.sign(nonces[index].first, km.secretShares[signerId], signerId.toUInt()).right!!
        }
        val signature = session.aggregateSigs(partials).right ?: return false
        return Crypto.verifySignatureSchnorr(message, signature, cache.tweakedPublicKey)
    }

    private fun subsets(n: Int, t: Int): List<List<Int>> {
        val result = mutableListOf<List<Int>>()
        fun visit(start: Int, selected: List<Int>) {
            if (selected.size == t) {
                result += selected
                return
            }
            for (next in start until n) visit(next + 1, selected + next)
        }
        visit(0, emptyList())
        return result
    }

    @Test
    fun refreshPreservesTheGroupKeyAndProducesValidShares() {
        for (n in 3..5) {
            for (t in 2..n) {
                val old = Frost.trustedDealerKeygen(thresholdSecretKey, n, t)
                val refreshed = refresh(old)
                val newSecrets = refreshed.candidates.map { it.secretShare }
                val newPublic = refreshed.candidates.first().publicShares

                refreshed.candidates.forEach { candidate ->
                    assertEquals(newPublic, candidate.publicShares)
                    assertEquals(candidate.secretShare.publicKey(), candidate.publicShares[newSecrets.indexOf(candidate.secretShare)])
                }
                assertTrue(newSecrets.zip(old.secretShares).all { (new, oldShare) -> new != oldShare })
                assertTrue(KeyMaterial(old.thresholdPublicKey, newSecrets, newPublic, t).isValid(), "n=$n t=$t")

                val independentlyDerived = FrostRefresh.derivePublicShares(
                    old.publicShares, refreshed.dealerShares.map { it.commitments }, sessionId,
                    old.thresholdPublicKey, 0, 1, ids(n), t,
                ).right!!
                assertEquals(newPublic, independentlyDerived)
            }
        }
    }

    @Test
    fun everyThresholdSubsetSignsAfterRefresh() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 5, 3)
        val refreshed = refresh(old)
        val updated = KeyMaterial(
            old.thresholdPublicKey,
            refreshed.candidates.map { it.secretShare },
            refreshed.candidates.first().publicShares,
            old.threshold,
        )
        subsets(5, 3).forEachIndexed { index, signerIds ->
            assertTrue(sign(updated, signerIds, index), "signer set $signerIds")
        }
    }

    @Test
    fun mixedOldAndNewSharesCannotSign() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 3, 2)
        val refreshed = refresh(old)
        val mixed = KeyMaterial(
            old.thresholdPublicKey,
            listOf(old.secretShares[0], refreshed.candidates[1].secretShare, refreshed.candidates[2].secretShare),
            refreshed.candidates.first().publicShares,
            2,
        )
        assertFalse(runCatching { sign(mixed, listOf(0, 1), 99) }.getOrDefault(false))
    }

    @Test
    fun anOldThresholdQuorumStillSignsForTheUnchangedKey() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 3, 2)
        refresh(old)
        // Refresh is not revocation. This test deliberately prevents documenting it as such.
        assertTrue(sign(old, listOf(0, 1), 100))
    }

    @Test
    fun corruptEvaluationNamesItsDealer() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val participantIds = ids(4)
        val dealerShares = participantIds.map { dealerId ->
            FrostRefresh.generateShares(seed(dealerId.toInt()), old.secretShares[dealerId.toInt()], sessionId, old.thresholdPublicKey, 0, 1, participantIds, dealerId, 2).right!!
        }
        val corrupted = dealerShares.mapIndexed { index, shares ->
            if (index == 2) shares.evaluations[3] + one else shares.evaluations[3]
        }
        val error = FrostRefresh.generateCandidate(
            old.secretShares[3], old.publicShares, corrupted, dealerShares.map { it.commitments },
            3u, sessionId, old.thresholdPublicKey, 0, 1, participantIds, 2,
        ).left
        val fault = assertIs<RefreshDealerFault>(error)
        assertEquals(2u, fault.dealerId)
    }

    @Test
    fun corruptCommitmentNamesItsDealer() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val participantIds = ids(4)
        val dealerShares = participantIds.map { dealerId ->
            FrostRefresh.generateShares(seed(dealerId.toInt()), old.secretShares[dealerId.toInt()], sessionId, old.thresholdPublicKey, 0, 1, participantIds, dealerId, 2).right!!
        }
        val commitments = dealerShares.map { it.commitments }.toMutableList()
        commitments[1] = commitments[1].map { -it }
        val error = FrostRefresh.generateCandidate(
            old.secretShares[3], old.publicShares, dealerShares.map { it.evaluations[3] }, commitments,
            3u, sessionId, old.thresholdPublicKey, 0, 1, participantIds, 2,
        ).left
        val fault = assertIs<RefreshDealerFault>(error)
        assertEquals(1u, fault.dealerId)
    }

    @Test
    fun recomputingASessionReproducesItsMessages() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 3, 2)
        val participantIds = ids(3)
        val first = FrostRefresh.generateShares(seed(1), old.secretShares[1], sessionId, old.thresholdPublicKey, 0, 1, participantIds, 1u, 2).right!!
        val second = FrostRefresh.generateShares(seed(1), old.secretShares[1], sessionId, old.thresholdPublicKey, 0, 1, participantIds, 1u, 2).right!!
        assertEquals(first, second)

        val differentSession = FrostRefresh.generateShares(seed(1), old.secretShares[1], sessionId, old.thresholdPublicKey, 1, 2, participantIds, 1u, 2).right!!
        assertNotEquals(first.paramsHash, differentSession.paramsHash)
        assertNotEquals(first.evaluations, differentSession.evaluations)
    }

    @Test
    fun paramsHashIsCanonicalAndBindsTheWholeRun() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        val participantIds = ids(4)
        val base = FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, participantIds, 2).right!!
        assertEquals(base, FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, participantIds.reversed(), 2).right!!)
        assertNotEquals(base, FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 1, 2, participantIds, 2).right!!)
        assertNotEquals(base, FrostRefresh.paramsHash(ByteVector32(ByteArray(32) { 0x11 }), old.thresholdPublicKey, 0, 1, participantIds, 2).right!!)
        assertNotEquals(base, FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, participantIds.dropLast(1), 2).right!!)
    }

    @Test
    fun invalidParametersAreRefused() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 4, 2)
        assertTrue(FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, ids(4), 1).isLeft)
        assertTrue(FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 2, ids(4), 2).isLeft)
        assertTrue(FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, listOf(0u, 0u), 2).isLeft)
        assertTrue(FrostRefresh.paramsHash(sessionId, old.thresholdPublicKey, 0, 1, listOf(0u, 1u, 4u), 2).isLeft)
        assertTrue(FrostRefresh.generateShares(seed(0), old.secretShares[0], sessionId, old.thresholdPublicKey, 0, 1, ids(4), 4u, 2).isLeft)
        assertTrue(FrostRefresh.generateCandidate(old.secretShares[0], old.publicShares, emptyList(), emptyList(), 0u, sessionId, old.thresholdPublicKey, 0, 1, ids(4), 2).isLeft)
    }

    @Test
    fun secretOutputsAreRedacted() {
        val old = Frost.trustedDealerKeygen(thresholdSecretKey, 3, 2)
        val refreshed = refresh(old)
        assertEquals("<refresh_shares>", refreshed.dealerShares.first().toString())
        assertEquals("<refresh_candidate>", refreshed.candidates.first().toString())
        assertFalse(refreshed.dealerShares.first().toString().contains(refreshed.dealerShares.first().evaluations.first().toHex()))
        assertFalse(refreshed.candidates.first().toString().contains(refreshed.candidates.first().secretShare.toHex()))
    }
}
