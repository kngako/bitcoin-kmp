@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce as Musig2IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.crypto.musig2.SecretNonce as Musig2SecretNonce
import fr.acinq.bitcoin.crypto.musig2.Session
import fr.acinq.bitcoin.utils.Either
import kotlin.random.Random
import kotlin.test.*

class PrefractalTestsCommon {
    // Two FIXED threshold secret keys, one of each Y parity of the resulting threshold public key. The nested
    // equation carries no frost-level key parity factor, and NOT because the tweak cache is the identity: stock
    // frost's factor is -1 for every odd-Y threshold key. Anything that reintroduced it would pass for even-Y
    // groups and fail for odd-Y ones, so a random fixture would catch it only half the time.
    private val thresholdSeckeyEven = PrivateKey.fromHex("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")
    private val thresholdSeckeyOdd = PrivateKey.fromHex("d327593fe753f6fde38f29fd2639d44f62054babea21a359a41d651c81f1e01e")
    private val cosignerPrivateKey = PrivateKey.fromHex("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1")

    private class Group(val n: Int, val t: Int, val km: KeyMaterial, val tweakCache: TweakCache) {
        val groupPublicKey: PublicKey get() = km.thresholdPublicKey
        val ids: List<UInt> = (0 until t).map { it.toUInt() }
        val signerPublicShares: List<PublicKey> get() = ids.map { km.publicShares[it.toInt()] }
    }

    private fun dealGroup(n: Int, t: Int, thresholdSeckey: PrivateKey): Group {
        val km = Frost.trustedDealerKeygen(thresholdSeckey, n, t)
        assertTrue(km.isValid())
        return Group(n, t, km, TweakCache.create(km.thresholdPublicKey))
    }

    /**
     * A full nested session against a stock musig2 cosigner, judged by a plain BIP340 verification of the outer
     * aggregate key.
     *
     * @param groupFirst which side of the outer key aggregation the group sits on. BIP327 gives the second
     * distinct key a coefficient of exactly 1, so the two orders are different arithmetic for the group.
     */
    private fun runSession(g: Group, groupFirst: Boolean, tweak: ByteVector32?): Boolean {
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()

        val publicKeys = if (groupFirst) listOf(g.groupPublicKey, cosignerPrivateKey.publicKey())
                         else listOf(cosignerPrivateKey.publicKey(), g.groupPublicKey)
        val (untweakedKey, cache0) = KeyAggCache.create(publicKeys)
        val (aggregatePublicKey, keyAggCache) = when (tweak) {
            null -> Pair(untweakedKey, cache0)
            else -> cache0.tweak(tweak, isXonly = true).right!!.let { Pair(it.second.xOnly(), it.first) }
        }

        // Round 1: every participating member derives its nonce from the label, before the message is known.
        val nonces = g.ids.map { id ->
            Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, sessionId, id)
        }
        val secretNonces = nonces.map { it.first }
        val publicNonces = nonces.map { it.second }
        val (groupPublicNonce, groupAggregatedNonce) = Prefractal.aggregateNonces(publicNonces, g.ids, g.groupPublicKey).right!!

        // The cosigner runs plain musig2.
        val (cosignerSecretNonce, cosignerPublicNonce) = Musig2SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val allNonces = if (groupFirst) listOf(groupPublicNonce, cosignerPublicNonce) else listOf(cosignerPublicNonce, groupPublicNonce)
        val aggregatedNonce = Musig2IndividualNonce.aggregate(allNonces).right!!
        val cosignerAggregatedNonce = Musig2IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right!!
        val session = Session.create(aggregatedNonce, msg, keyAggCache)

        // Round 2.
        val cosignerPartialSig = session.sign(cosignerSecretNonce, cosignerPrivateKey).right!!
        val shares = g.ids.mapIndexed { i, id ->
            Prefractal.partialSign(secretNonces[i], g.km.secretShares[id.toInt()], id, g.ids, g.signerPublicShares,
                                   groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce).right!!
        }
        shares.forEachIndexed { i, share ->
            assertTrue(Prefractal.verifyPartialSignature(share, publicNonces[i], g.km.publicShares[g.ids[i].toInt()], g.ids[i],
                                                         g.ids, groupAggregatedNonce, g.groupPublicKey, g.tweakCache,
                                                         keyAggCache, msg, cosignerAggregatedNonce))
        }
        val groupPartialSig = Prefractal.aggregatePartialSignatures(shares, g.tweakCache).right!!
        // The group's contribution is an ordinary musig2 partial signature: the outer session verifies it as one.
        assertTrue(session.verify(groupPartialSig, groupPublicNonce, g.groupPublicKey))

        val all = if (groupFirst) listOf(groupPartialSig, cosignerPartialSig) else listOf(cosignerPartialSig, groupPartialSig)
        val sig = session.aggregateSigs(all).right!!
        return Crypto.verifySignatureSchnorr(msg, sig, aggregatePublicKey)
    }

    @Test
    fun `nested group signing session`() {
        for ((n, t) in listOf(2 to 2, 3 to 2, 5 to 3, 4 to 3)) {
            for (groupFirst in listOf(true, false)) {
                for (seckey in listOf(thresholdSeckeyEven, thresholdSeckeyOdd)) {
                    for (tweak in listOf(null, Random.nextBytes(32).byteVector32())) {
                        val g = dealGroup(n, t, seckey)
                        assertTrue(runSession(g, groupFirst, tweak), "failed for $t-of-$n groupFirst=$groupFirst tweaked=${tweak != null}")
                    }
                }
            }
        }
    }

    /**
     * The odd-Y group key on its own, so a regression names its cause instead of surfacing as one iteration of the
     * matrix above.
     */
    @Test
    fun `odd-Y group key`() {
        val g = dealGroup(3, 2, thresholdSeckeyOdd)
        // The fixture really is odd-Y, so this test cannot quietly stop testing what it is named after.
        assertEquals(0x03.toByte(), g.groupPublicKey.value[0])
        assertTrue(runSession(g, true, null))
    }

    /**
     * Nonces are a pure function of the share and the session label. This is what lets round two re-derive what
     * round one published without storing anything, and what lets a restarted signer reproduce a nonce it
     * published before. It is also why one label must sign only one message.
     */
    @Test
    fun `nonce derivation is deterministic in the session label`() {
        val g = dealGroup(3, 2, thresholdSeckeyOdd)
        val sessionId = Random.nextBytes(32).byteVector32()
        val (_, pub1) = Prefractal.generateNonce(g.km.secretShares[0], g.km.publicShares[0], g.groupPublicKey, sessionId, 0u)
        val (_, pub2) = Prefractal.generateNonce(g.km.secretShares[0], g.km.publicShares[0], g.groupPublicKey, sessionId, 0u)
        assertEquals(pub1, pub2)

        // Different label, different nonce.
        val other = Random.nextBytes(32).byteVector32()
        val (_, pub3) = Prefractal.generateNonce(g.km.secretShares[0], g.km.publicShares[0], g.groupPublicKey, other, 0u)
        assertNotEquals(pub1, pub3)

        // Different member under the same label, different nonce: the label is per-member.
        val (_, pub4) = Prefractal.generateNonce(g.km.secretShares[1], g.km.publicShares[1], g.groupPublicKey, sessionId, 1u)
        assertNotEquals(pub1, pub4)
    }

    /** A secret nonce is single use, enforced here rather than by the bindings underneath. */
    @Test
    fun `secret nonce is single use`() {
        val g = dealGroup(3, 2, thresholdSeckeyOdd)
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()
        val publicKeys = listOf(g.groupPublicKey, cosignerPrivateKey.publicKey())
        val (_, keyAggCache) = KeyAggCache.create(publicKeys)

        val nonces = g.ids.map { id -> Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, sessionId, id) }
        val (_, groupAggregatedNonce) = Prefractal.aggregateNonces(nonces.map { it.second }, g.ids, g.groupPublicKey).right!!
        val (cosignerSecretNonce, cosignerPublicNonce) = Musig2SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val cosignerAggregatedNonce = Musig2IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right!!
        assertNotNull(cosignerSecretNonce)

        val secretNonce = nonces[0].first
        assertNotNull(Prefractal.partialSign(secretNonce, g.km.secretShares[0], 0u, g.ids, g.signerPublicShares,
                                             groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce).right)
        // The second attempt is refused by SecretNonce itself, not by libsecp256k1.
        val second = Prefractal.partialSign(secretNonce, g.km.secretShares[0], 0u, g.ids, g.signerPublicShares,
                                            groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce)
        assertNull(second.right)
        assertTrue(second.left is IllegalStateException)
    }

    /** A tweaked frost cache is refused: only the outer aggregate key is tweaked in this composition. */
    @Test
    fun `frost tweak cache must be the identity`() {
        val g = dealGroup(3, 2, thresholdSeckeyOdd)
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()
        val publicKeys = listOf(g.groupPublicKey, cosignerPrivateKey.publicKey())
        val (_, keyAggCache) = KeyAggCache.create(publicKeys)
        // tweak() returns a NEW cache rather than mutating in place.
        val tweaked = TweakCache.create(g.groupPublicKey).tweak(Random.nextBytes(32).byteVector32(), isXonly = true).right!!.first
        assertNotEquals(g.tweakCache, tweaked)

        val nonces = g.ids.map { id -> Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, sessionId, id) }
        val (_, groupAggregatedNonce) = Prefractal.aggregateNonces(nonces.map { it.second }, g.ids, g.groupPublicKey).right!!
        val (_, cosignerPublicNonce) = Musig2SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val cosignerAggregatedNonce = Musig2IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right!!

        assertNull(Prefractal.partialSign(nonces[0].first, g.km.secretShares[0], 0u, g.ids, g.signerPublicShares,
                                          groupAggregatedNonce, g.groupPublicKey, tweaked, keyAggCache, msg, cosignerAggregatedNonce).right)
        // The identity cache is accepted at the same call, so the refusal is about the tweak.
        assertNotNull(Prefractal.partialSign(nonces[1].first, g.km.secretShares[1], 1u, g.ids, g.signerPublicShares,
                                             groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce).right)
    }

    /**
     * The wrong outer key order produces shares that are individually well formed and only fail at the final
     * BIP340 verification. This is the failure class the API cannot catch for the caller.
     */
    @Test
    fun `wrong outer key order is caught only by the final signature`() {
        val g = dealGroup(3, 2, thresholdSeckeyOdd)
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()
        val publicKeys = listOf(g.groupPublicKey, cosignerPrivateKey.publicKey())
        val (aggregatePublicKey, _) = KeyAggCache.create(publicKeys)
        // The group signs under a cache built from the same keys in the other order.
        val (_, wrongCache) = KeyAggCache.create(publicKeys.reversed())

        val nonces = g.ids.map { id -> Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, sessionId, id) }
        val (groupPublicNonce, groupAggregatedNonce) = Prefractal.aggregateNonces(nonces.map { it.second }, g.ids, g.groupPublicKey).right!!
        val (cosignerSecretNonce, cosignerPublicNonce) = Musig2SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, wrongCache, null)
        val aggregatedNonce = Musig2IndividualNonce.aggregate(listOf(groupPublicNonce, cosignerPublicNonce)).right!!
        val cosignerAggregatedNonce = Musig2IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right!!
        val session = Session.create(aggregatedNonce, msg, wrongCache)

        val cosignerPartialSig = session.sign(cosignerSecretNonce, cosignerPrivateKey).right!!
        val shares = g.ids.mapIndexed { i, id ->
            Prefractal.partialSign(nonces[i].first, g.km.secretShares[id.toInt()], id, g.ids, g.signerPublicShares,
                                   groupAggregatedNonce, g.groupPublicKey, g.tweakCache, wrongCache, msg, cosignerAggregatedNonce).right!!
        }
        // Every share is valid against the (wrong) session it was made for.
        shares.forEachIndexed { i, share ->
            assertTrue(Prefractal.verifyPartialSignature(share, nonces[i].second, g.km.publicShares[g.ids[i].toInt()], g.ids[i],
                                                         g.ids, groupAggregatedNonce, g.groupPublicKey, g.tweakCache,
                                                         wrongCache, msg, cosignerAggregatedNonce))
        }
        val groupPartialSig = Prefractal.aggregatePartialSignatures(shares, g.tweakCache).right!!
        val sig = session.aggregateSigs(listOf(groupPartialSig, cosignerPartialSig)).right!!
        // ...and the result does not verify against the key the caller meant to spend.
        assertFalse(Crypto.verifySignatureSchnorr(msg, sig, aggregatePublicKey))
    }

    /** Verification rejects a tampered share, the wrong member, and a share made for another signer set. */
    @Test
    fun `partial signature verification rejects`() {
        val g = dealGroup(5, 3, thresholdSeckeyOdd)
        val msg = Random.nextBytes(32).byteVector32()
        val sessionId = Random.nextBytes(32).byteVector32()
        val publicKeys = listOf(g.groupPublicKey, cosignerPrivateKey.publicKey())
        val (_, keyAggCache) = KeyAggCache.create(publicKeys)

        val nonces = g.ids.map { id -> Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, sessionId, id) }
        val (_, groupAggregatedNonce) = Prefractal.aggregateNonces(nonces.map { it.second }, g.ids, g.groupPublicKey).right!!
        val (_, cosignerPublicNonce) = Musig2SecretNonce.generate(Random.nextBytes(32).byteVector32(), Either.Left(cosignerPrivateKey), msg, keyAggCache, null)
        val cosignerAggregatedNonce = Musig2IndividualNonce.aggregate(listOf(cosignerPublicNonce)).right!!

        val share = Prefractal.partialSign(nonces[0].first, g.km.secretShares[0], 0u, g.ids, g.signerPublicShares,
                                           groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce).right!!
        assertTrue(Prefractal.verifyPartialSignature(share, nonces[0].second, g.km.publicShares[0], 0u, g.ids,
                                                     groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce))

        val tampered = ByteVector32(share.toByteArray().also { it[10] = (it[10].toInt() xor 0x40).toByte() })
        assertFalse(Prefractal.verifyPartialSignature(tampered, nonces[0].second, g.km.publicShares[0], 0u, g.ids,
                                                      groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce))

        assertFalse(Prefractal.verifyPartialSignature(share, nonces[1].second, g.km.publicShares[1], 1u, g.ids,
                                                      groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce))

        // A different signer set: the Lagrange coefficients are defined over the participating set.
        val otherIds = listOf(0u, 1u, 3u)
        assertFalse(Prefractal.verifyPartialSignature(share, nonces[0].second, g.km.publicShares[0], 0u, otherIds,
                                                      groupAggregatedNonce, g.groupPublicKey, g.tweakCache, keyAggCache, msg, cosignerAggregatedNonce))
    }

    /** Invalid arguments come back as Either.Left rather than throwing. */
    @Test
    fun `invalid inputs`() {
        val g = dealGroup(3, 2, thresholdSeckeyEven)
        assertNull(Prefractal.aggregateNonces(listOf(), listOf(), g.groupPublicKey).right)
        val nonces = g.ids.map { id -> Prefractal.generateNonce(g.km.secretShares[id.toInt()], g.km.publicShares[id.toInt()], g.groupPublicKey, ByteVector32.Zeroes, id) }
        // Duplicate identifiers make the Lagrange coefficients undefined.
        assertNull(Prefractal.aggregateNonces(nonces.map { it.second }, listOf(0u, 0u), g.groupPublicKey).right)
        assertNull(Prefractal.aggregatePartialSignatures(listOf(), g.tweakCache).right)
    }
}
