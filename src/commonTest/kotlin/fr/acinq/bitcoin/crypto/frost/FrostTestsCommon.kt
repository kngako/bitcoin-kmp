package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.*
import kotlin.random.Random
import kotlin.test.*

class FrostTestsCommon {
    @Test
    fun `generate threshold key material with trusted dealer`() {
        val thresholdSecretKey = PrivateKey.fromHex("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54")
        val keyMaterial = Frost.trustedDealerKeygen(thresholdSecretKey, 3, 2)
        assertEquals(3, keyMaterial.nParticipants)
        assertEquals(2, keyMaterial.threshold)
        assertEquals(3, keyMaterial.secretShares.size)
        assertEquals(3, keyMaterial.publicShares.size)
        // Each public share is the public key of the corresponding secret share.
        keyMaterial.secretShares.forEachIndexed { i, secretShare ->
            assertEquals(secretShare.publicKey(), keyMaterial.publicShares[i])
        }
        // Key material is consistent.
        assertTrue(keyMaterial.isValid())
        // A tampered public share is rejected.
        val badPublicShares = keyMaterial.publicShares.toMutableList().apply { this[1] = PrivateKey(ByteArray(32) { 0x11 }).publicKey() }
        assertFalse(keyMaterial.copy(publicShares = badPublicShares).isValid())
        // A wrong threshold public key is rejected.
        assertFalse(keyMaterial.copy(thresholdPublicKey = PrivateKey(ByteArray(32) { 0x22 }).publicKey()).isValid())
    }

    @Test
    fun `simple frost example`() {
        val msg = Random.nextBytes(32).byteVector32()
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(ByteArray(32) { 1 }), 3, 2)

        val plainTweak = ByteVector32("this could be a BIP32 tweak....".encodeToByteArray() + ByteArray(1))
        val xonlyTweak = ByteVector32("this could be a taproot tweak..".encodeToByteArray() + ByteArray(1))

        // Apply tweaks to the threshold public key.
        val (tweakCache, tweakedPublicKey) = run {
            val (c1, _) = keyMaterial.tweakCache().tweak(plainTweak, false).right!!
            c1.tweak(xonlyTweak, true).right!!
        }
        assertEquals(tweakedPublicKey, tweakCache.tweakedPublicKey)

        // Signers 0 and 2 (non-contiguous ids) generate their nonces.
        val signerIds = listOf(0u, 2u)
        val nonces = signerIds.map { id ->
            SecretNonce.generate(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[id.toInt()], keyMaterial.publicShares[id.toInt()], tweakedPublicKey, msg, null)
        }
        val secretNonces = nonces.map { it.first }
        val publicNonces = nonces.map { it.second }

        // The coordinator aggregates the public nonces.
        val aggregatedNonce = IndividualNonce.aggregate(publicNonces).right
        assertNotNull(aggregatedNonce)

        // All signers and the coordinator create the same signing session.
        val session = Session.create(aggregatedNonce, signerIds, keyMaterial.publicSharesOf(signerIds), keyMaterial.nParticipants, keyMaterial.threshold, tweakCache, msg)

        // Each signer creates a partial signature.
        val partialSigs = signerIds.mapIndexed { i, id -> session.sign(secretNonces[i], keyMaterial.secretShares[id.toInt()], id).right!! }
        // The coordinator verifies each partial signature.
        signerIds.forEachIndexed { i, id ->
            assertTrue(session.verify(partialSigs[i], publicNonces[i], keyMaterial.publicShares[id.toInt()], i))
        }
        // A partial signature from signer 0 must not verify as signer 1's.
        assertFalse(session.verify(partialSigs[0], publicNonces[1], keyMaterial.publicShares[2], 1))

        // The coordinator aggregates the partial signatures into a single schnorr signature.
        val aggregateSig = session.aggregateSigs(partialSigs).right
        assertNotNull(aggregateSig)
        // The aggregated signature is a valid, plain schnorr signature for the tweaked threshold public key.
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggregateSig, tweakedPublicKey))
    }

    @Test
    fun `sign arbitrary messages with frost`() {
        val msg = Random.nextBytes(32).byteVector32()
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(Random.nextBytes(32)), 5, 3)
        assertTrue(keyMaterial.isValid())

        // 3-of-5 signature with non-contiguous signer ids.
        val signerIds = listOf(0u, 2u, 4u)
        val nonces = signerIds.map { id ->
            Frost.generateNonce(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[id.toInt()], keyMaterial.publicShares[id.toInt()], keyMaterial.tweakCache().tweakedPublicKey, msg, null)
        }
        val publicNonces = nonces.map { it.second }

        val partialSigs = signerIds.mapIndexed { i, id ->
            val sig = Frost.sign(keyMaterial.secretShares[id.toInt()], nonces[i].first, id, msg, signerIds, keyMaterial, publicNonces).right
            assertNotNull(sig)
            assertTrue(Frost.verify(sig, publicNonces[i], keyMaterial.publicShares[id.toInt()], i, msg, signerIds, keyMaterial, publicNonces))
            // Wrong nonce.
            assertFalse(Frost.verify(sig, publicNonces[(i + 1) % 3], keyMaterial.publicShares[id.toInt()], i, msg, signerIds, keyMaterial, publicNonces))
            // Wrong public share.
            assertFalse(Frost.verify(sig, publicNonces[i], keyMaterial.publicShares[(id.toInt() + 1) % 5], i, msg, signerIds, keyMaterial, publicNonces))
            // Wrong signer index.
            assertFalse(Frost.verify(sig, publicNonces[i], keyMaterial.publicShares[id.toInt()], (i + 1) % 3, msg, signerIds, keyMaterial, publicNonces))
            sig
        }

        val aggregateSig = Frost.aggregatePartialSignatures(partialSigs, msg, signerIds, keyMaterial, publicNonces).right
        assertNotNull(aggregateSig)
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggregateSig, keyMaterial.tweakCache().tweakedPublicKey))
    }

    @Test
    fun `secret nonces are single use`() {
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(ByteArray(32) { 1 }), 2, 2)
        val tweakCache = keyMaterial.tweakCache()
        val signerIds = listOf(0u, 1u)

        val (aliceSecretNonce, alicePublicNonce) = SecretNonce.generate(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[0], keyMaterial.publicShares[0], tweakCache.tweakedPublicKey, null, null)
        val (_, bobPublicNonce) = SecretNonce.generate(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[1], keyMaterial.publicShares[1], tweakCache.tweakedPublicKey, null, null)

        val aggregatedNonce = IndividualNonce.aggregate(listOf(alicePublicNonce, bobPublicNonce)).right
        assertNotNull(aggregatedNonce)

        val firstSession = Session.create(aggregatedNonce, signerIds, keyMaterial.publicShares, keyMaterial.nParticipants, keyMaterial.threshold, tweakCache, ByteVector32(ByteArray(31) + byteArrayOf(1)))
        val firstSig = firstSession.sign(aliceSecretNonce, keyMaterial.secretShares[0], 0u).right!!
        assertTrue(firstSession.verify(firstSig, alicePublicNonce, keyMaterial.publicShares[0], 0))

        val secondSession = Session.create(aggregatedNonce, signerIds, keyMaterial.publicShares, keyMaterial.nParticipants, keyMaterial.threshold, tweakCache, ByteVector32(ByteArray(31) + byteArrayOf(2)))
        val error = assertIs<IllegalStateException>(secondSession.sign(aliceSecretNonce, keyMaterial.secretShares[0], 0u).left)
        assertEquals("secret nonce has already been used", error.message)
    }

    @Test
    fun `use frost to replace multisig 2-of-3`() {
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(ByteArray(32) { 1 }), 3, 2)
        // The participants agree on the threshold public key, which they use as their taproot internal key.
        val internalPubKey = keyMaterial.thresholdPublicKey.xOnly()

        // Signers 0 and 2 (2-of-3) will collaboratively sign: participant 1 is not involved.
        val signerIds = listOf(0u, 2u)
        val signerSecretShares = signerIds.map { keyMaterial.secretShares[it.toInt()] }

        // This tx sends to a taproot script that doesn't contain any script path.
        val tx = Transaction(2, listOf(), listOf(TxOut(10_000.sat(), Script.pay2tr(internalPubKey, Crypto.TaprootTweak.KeyPathTweak))), 0)
        // This tx spends the previous tx with a threshold signature from participants 0 and 2.
        val spendingTx = Transaction(2, listOf(TxIn(OutPoint(tx, 0), sequence = 0)), listOf(TxOut(10_000.sat(), Script.pay2wpkh(keyMaterial.publicShares[0]))), 0)

        // The first step of a frost signing session is to exchange nonces.
        // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
        val nonces = signerSecretShares.mapIndexed { i, secretShare ->
            Frost.generateNonce(Random.nextBytes(32).byteVector32(), secretShare, keyMaterial.publicShares[signerIds[i].toInt()], null, null, null)
        }
        val publicNonces = nonces.map { it.second }

        // Once they have each other's public nonce, they can produce partial signatures.
        val partialSigs = signerIds.mapIndexed { i, id ->
            val sig = Frost.signTaprootInput(signerSecretShares[i], nonces[i].first, id, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null).right
            assertNotNull(sig)
            assertTrue(Frost.verify(sig, publicNonces[i], keyMaterial.publicShares[id.toInt()], i, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null))
            sig
        }

        // Once they have each other's partial signature, they can aggregate them into a valid signature.
        val aggregateSig = Frost.aggregateTaprootSignatures(partialSigs, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null).right
        assertNotNull(aggregateSig)

        // This tx looks like any other tx that spends a p2tr output, with a single signature.
        val signedSpendingTx = spendingTx.updateWitness(0, Script.witnessKeyPathPay2tr(aggregateSig))
        Transaction.correctlySpends(signedSpendingTx, tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `use frost with taproot script tree`() {
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(ByteArray(32) { 2 }), 3, 2)
        val internalPubKey = keyMaterial.thresholdPublicKey.xOnly()
        val userRefundPrivateKey = PrivateKey(ByteArray(32) { 3 })
        val refundDelay = 25920

        // The redeem script is just the refund script, generated from this policy: and_v(v:pk(user),older(refundDelay))
        val redeemScript = listOf(OP_PUSHDATA(userRefundPrivateKey.xOnlyPublicKey()), OP_CHECKSIGVERIFY, OP_PUSHDATA(Script.encodeNumber(refundDelay)), OP_CHECKSEQUENCEVERIFY)
        val scriptTree = ScriptTree.Leaf(redeemScript)
        val pubkeyScript = Script.pay2tr(internalPubKey, scriptTree)

        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(),
            txOut = listOf(TxOut(10_000.sat(), pubkeyScript)),
            lockTime = 0
        )

        // The transaction can be spent if 2 of the 3 participants produce a signature.
        run {
            val signerIds = listOf(0u, 1u)
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(10_000.sat(), Script.pay2wpkh(keyMaterial.publicShares[0]))),
                lockTime = 0
            )
            // The first step of a frost signing session is to exchange nonces.
            val nonces = signerIds.map { id ->
                Frost.generateNonce(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[id.toInt()], keyMaterial.publicShares[id.toInt()], null, null, null)
            }
            val publicNonces = nonces.map { it.second }

            // Once they have each other's public nonce, they can produce partial signatures.
            val partialSigs = signerIds.mapIndexed { i, id ->
                val sig = Frost.signTaprootInput(keyMaterial.secretShares[id.toInt()], nonces[i].first, id, tx, 0, swapInTx.txOut, signerIds, keyMaterial, publicNonces, scriptTree).right
                assertNotNull(sig)
                assertTrue(Frost.verify(sig, publicNonces[i], keyMaterial.publicShares[id.toInt()], i, tx, 0, swapInTx.txOut, signerIds, keyMaterial, publicNonces, scriptTree))
                sig
            }

            // Once they have each other's partial signature, they can aggregate them into a valid signature.
            val aggregateSig = Frost.aggregateTaprootSignatures(partialSigs, tx, 0, swapInTx.txOut, signerIds, keyMaterial, publicNonces, scriptTree).right
            assertNotNull(aggregateSig)
            val signedTx = tx.updateWitness(0, Script.witnessKeyPathPay2tr(aggregateSig))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }

        // Or it can be spent with only the refund key's signature, after a delay.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = refundDelay.toLong())),
                txOut = listOf(TxOut(10_000.sat(), Script.pay2wpkh(keyMaterial.publicShares[0]))),
                lockTime = 0
            )
            val sig = Transaction.signInputTaprootScriptPath(userRefundPrivateKey, tx, 0, swapInTx.txOut, SigHash.SIGHASH_DEFAULT, scriptTree.hash())
            val signedTx = tx.updateWitness(0, Script.witnessScriptPathPay2tr(internalPubKey, scriptTree, ScriptWitness(listOf(sig)), scriptTree))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

    @Test
    fun `verify frost signatures`() {
        val keyMaterial = Frost.trustedDealerKeygen(PrivateKey(ByteArray(32) { 1 }), 3, 2)
        val internalPubKey = keyMaterial.thresholdPublicKey.xOnly()
        val signerIds = listOf(0u, 1u)

        val tx = Transaction(2, listOf(), listOf(TxOut(10_000.sat(), Script.pay2tr(internalPubKey, Crypto.TaprootTweak.KeyPathTweak))), 0)
        val spendingTx = Transaction(2, listOf(TxIn(OutPoint(tx, 0), sequence = 0)), listOf(TxOut(10_000.sat(), Script.pay2wpkh(keyMaterial.publicShares[0]))), 0)

        val nonces = signerIds.map { id ->
            Frost.generateNonce(Random.nextBytes(32).byteVector32(), keyMaterial.secretShares[id.toInt()], keyMaterial.publicShares[id.toInt()], null, null, null)
        }
        val publicNonces = nonces.map { it.second }

        val aliceSig = Frost.signTaprootInput(keyMaterial.secretShares[0], nonces[0].first, 0u, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null).right
        require(aliceSig != null)
        assertTrue(Frost.verify(aliceSig, publicNonces[0], keyMaterial.publicShares[0], 0, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null))

        // wrong signature
        assertFalse(Frost.verify(aliceSig.reversed(), publicNonces[0], keyMaterial.publicShares[0], 0, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null))

        // wrong public share
        assertFalse(Frost.verify(aliceSig, publicNonces[0], keyMaterial.publicShares[2], 0, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null))

        // wrong nonce
        assertFalse(Frost.verify(aliceSig, publicNonces[0], keyMaterial.publicShares[0], 0, spendingTx, 0, listOf(tx.txOut[0]), signerIds, keyMaterial, listOf(publicNonces[0], publicNonces[0]), scriptTree = null))

        // wrong inputs
        assertFalse(Frost.verify(aliceSig, publicNonces[0], keyMaterial.publicShares[0], 0, spendingTx, 0, listOf(tx.txOut[0], tx.txOut[0]), signerIds, keyMaterial, publicNonces, scriptTree = null))
    }
}
