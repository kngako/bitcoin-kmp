package fr.acinq.bitcoin.crypto.iceberg

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.Session
import fr.acinq.bitcoin.crypto.musig2.SecretNonce
import fr.acinq.bitcoin.utils.Either
import kotlin.random.Random
import kotlin.test.*

class IcebergTestsCommon {
    private val seed = ByteVector32.fromValidHex("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54")
    private val cosignerPrivateKey = PrivateKey.fromHex("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1")

    /** Deal a 2-of-4 group and return its shares, public shares and group public key. */
    private fun dealGroup(): Triple<List<Share>, List<PublicShare>, PublicKey> {
        val shares = Iceberg.dealShares(4, 2, seed)
        assertEquals(4, shares.size)
        // 2-of-4 shares hold C(3, 1) = 3 seeds each.
        shares.forEach { assertEquals(4 + 32 * 3, it.toByteArray().size) }
        val caches = shares.map { Iceberg.shareCache(it) }
        val publicShares = shares.mapIndexed { i, share -> Iceberg.publicShare(share, caches[i]) }
        val groupPublicKey = Iceberg.groupPublicKey(publicShares, 4, 2).right
        assertNotNull(groupPublicKey)
        return Triple(shares, publicShares, groupPublicKey)
    }

    @Test
    fun `group signing session`() {
        val (shares, publicShares, groupPublicKey) = dealGroup()
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()

        // The group participates in an outer musig2 session alongside a cosigner, as if it were a single signer.
        val publicKeys = listOf(groupPublicKey, cosignerPrivateKey.publicKey())
        val (aggregatePublicKey, keyAggCache) = KeyAggCache.create(publicKeys)
        assertTrue(Iceberg.keyAggregationCheck(keyAggCache, publicKeys, groupPublicKey))
        assertFalse(Iceberg.keyAggregationCheck(keyAggCache, publicKeys, PrivateKey(ByteArray(32) { 0x09 }).publicKey()))
        assertFalse(Iceberg.keyAggregationCheck(keyAggCache, publicKeys.reversed(), groupPublicKey))

        // Round 1: a quorum of 2t-1 = 3 members publishes its nonce contribution (before the message is known).
        val contributingMembers = listOf(0, 1, 2)
        val nonceContributions = contributingMembers.map { Iceberg.generateNonce(shares[it], null, sessionId) }
        // The group's contributions combine into one ordinary musig2 public nonce.
        val groupPublicNonce = Iceberg.aggregateNonces(nonceContributions, 4, 2, groupPublicKey).right
        assertNotNull(groupPublicNonce)

        // The cosigner generates a regular musig2 nonce, and the outer session starts.
        val (cosignerSecretNonce, cosignerPublicNonce) = SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val aggregatedNonce = IndividualNonce.aggregate(listOf(groupPublicNonce, cosignerPublicNonce)).right
        assertNotNull(aggregatedNonce)
        val cosignerAggregatedNonce = IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right
        assertNotNull(cosignerAggregatedNonce)
        val session = Session.create(aggregatedNonce, msg, keyAggCache)

        // Round 2: the cosigner signs with plain musig2, the group members with iceberg.
        val cosignerPartialSig = session.sign(cosignerSecretNonce, cosignerPrivateKey).right
        assertNotNull(cosignerPartialSig)
        val signatureShares = contributingMembers.map {
            Iceberg.partialSign(shares[it], null, sessionId, nonceContributions, groupPublicKey, keyAggCache, msg, cosignerAggregatedNonce).right!!
        }
        signatureShares.forEachIndexed { i, signatureShare ->
            assertTrue(Iceberg.verifyPartialSignature(signatureShare, publicShares[contributingMembers[i]], nonceContributions, 4, 2, groupPublicKey, keyAggCache, msg, cosignerAggregatedNonce))
        }
        // A signature share does not verify against another member's public share.
        assertFalse(Iceberg.verifyPartialSignature(signatureShares[0], publicShares[3], nonceContributions, 4, 2, groupPublicKey, keyAggCache, msg, cosignerAggregatedNonce))

        // The group's signature shares combine into one ordinary musig2 partial signature.
        val groupPartialSig = Iceberg.aggregatePartialSignatures(signatureShares, 4, 2).right
        assertNotNull(groupPartialSig)
        assertTrue(session.verify(groupPartialSig, groupPublicNonce, groupPublicKey))

        // The final signature is a plain BIP340 signature for the aggregated public key.
        val sig = session.aggregateSigs(listOf(groupPartialSig, cosignerPartialSig)).right
        assertNotNull(sig)
        assertTrue(Crypto.verifySignatureSchnorr(msg, sig, aggregatePublicKey))
    }

    @Test
    fun `group signing session with share caches and minimal quorum`() {
        val (shares, _, groupPublicKey) = dealGroup()
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()
        val caches = shares.map { Iceberg.shareCache(it) }

        val publicKeys = listOf(groupPublicKey, cosignerPrivateKey.publicKey())
        val (_, keyAggCache) = KeyAggCache.create(publicKeys)

        // A quorum of 3 members contributes nonces, using their share caches.
        val contributingMembers = listOf(0, 2, 3)
        val nonceContributions = contributingMembers.map { Iceberg.generateNonce(shares[it], caches[it], sessionId) }
        val groupPublicNonce = Iceberg.aggregateNonces(nonceContributions, 4, 2, groupPublicKey).right
        assertNotNull(groupPublicNonce)

        val (cosignerSecretNonce, cosignerPublicNonce) = SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val aggregatedNonce = IndividualNonce.aggregate(listOf(groupPublicNonce, cosignerPublicNonce)).right
        assertNotNull(aggregatedNonce)
        val cosignerAggregatedNonce = IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right
        assertNotNull(cosignerAggregatedNonce)
        val session = Session.create(aggregatedNonce, msg, keyAggCache)
        val cosignerPartialSig = session.sign(cosignerSecretNonce, cosignerPrivateKey).right
        assertNotNull(cosignerPartialSig)

        val signatureShares = contributingMembers.map {
            Iceberg.partialSign(shares[it], caches[it], sessionId, nonceContributions, groupPublicKey, keyAggCache, msg, cosignerAggregatedNonce).right!!
        }
        // Exactly t = 2 shares are enough to aggregate.
        val groupPartialSig = Iceberg.aggregatePartialSignatures(signatureShares.take(2), 4, 2).right
        assertNotNull(groupPartialSig)
        val sig = session.aggregateSigs(listOf(groupPartialSig, cosignerPartialSig)).right
        assertNotNull(sig)
        assertTrue(Crypto.verifySignatureSchnorr(msg, sig, KeyAggCache.create(publicKeys).first))
    }

    @Test
    fun `invalid inputs`() {
        val (shares, publicShares, groupPublicKey) = dealGroup()
        val sessionId = Random.nextBytes(32).byteVector32()

        // 2-of-2 is inexpressible: the quorum 2t-1 must fit in the group.
        assertFails { Iceberg.dealShares(2, 2, seed) }
        assertFails { Iceberg.dealShares(4, 3, seed) }
        // Too many participants.
        assertFails { Iceberg.dealShares(11, 2, seed) }
        // Too few contributions.
        val twoContributions = listOf(0, 1).map { Iceberg.generateNonce(shares[it], null, sessionId) }
        assertTrue(Iceberg.aggregateNonces(twoContributions, 4, 2, groupPublicKey).isLeft)
        // Duplicate contribution.
        val threeContributions = listOf(0, 1, 2).map { Iceberg.generateNonce(shares[it], null, sessionId) }
        assertTrue(Iceberg.aggregateNonces(listOf(threeContributions[0], threeContributions[0], threeContributions[1]), 4, 2, groupPublicKey).isLeft)
        // A malformed share or public share is rejected.
        assertFails { Iceberg.publicShare(Share(ByteArray(100)), null) }
        assertTrue(Iceberg.groupPublicKey(listOf(PublicShare(ByteArray(34))), 4, 2).isLeft)
        // Inconsistent public shares are rejected (member 2's entry is replaced with member 3's share).
        val tamperedPublicShares = publicShares.toMutableList().apply { this[1] = Iceberg.publicShare(shares[2], null) }
        assertTrue(Iceberg.groupPublicKey(tamperedPublicShares, 4, 2).isLeft)
    }
}
