package fr.acinq.bitcoin.crypto.dkg.chill

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.frost.IndividualNonce
import fr.acinq.bitcoin.crypto.frost.SecretNonce
import fr.acinq.bitcoin.crypto.frost.Session
import fr.acinq.bitcoin.crypto.frost.TweakCache
import fr.acinq.secp256k1.ChilldkgFault
import kotlin.random.Random
import kotlin.test.*

class ChillDKGTestsCommon {
    private val hostSecretKeys = listOf(
        PrivateKey.fromHex("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54"),
        PrivateKey.fromHex("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1"),
        PrivateKey.fromHex("0B1E9E1C5FDC56B9E90201C0C14DE3A9FF4A0DF7B839D18A29E9087F612480B7")
    )

    /** Run a complete 2-of-3 ChillDKG session and return the host public keys and each party's finalization result. */
    private fun runDkg(): Pair<List<PublicKey>, Pair<List<ParticipantFinalizeResult>, CoordinatorFinalizeResult>> {
        val n = hostSecretKeys.size
        val threshold = 2
        val hostPublicKeys = hostSecretKeys.map { ChillDKG.hostPublicKey(it) }

        // All participants agree on the session parameters.
        val paramsHash = ChillDKG.sessionParamsHash(hostPublicKeys, threshold)
        assertEquals(paramsHash, ChillDKG.sessionParamsHash(hostPublicKeys, threshold))

        // 1. Every participant runs step1 and sends its message to the coordinator.
        val step1 = hostSecretKeys.mapIndexed { i, hostSecretKey ->
            ChillDKG.participantStep1(hostSecretKey, hostPublicKeys, threshold, ByteVector32(Random.nextBytes(32)))
        }
        // 2. The coordinator aggregates the participants' messages and broadcasts its own message.
        val coordinatorStep1 = ChillDKG.coordinatorStep1(step1.map { it.message }, hostPublicKeys, threshold)
        assertTrue(coordinatorStep1.fault.isOk)
        assertNull(coordinatorStep1.fault.participantIndex)
        // 3. Every participant verifies the coordinator's message and sends its CertEq signature to the coordinator.
        val step2 = hostSecretKeys.mapIndexed { i, hostSecretKey ->
            val result = ChillDKG.participantStep2(hostSecretKey, step1[i].state, coordinatorStep1.message, ByteVector32(Random.nextBytes(32)))
            assertTrue(result.fault.isOk)
            assertNull(result.investigationData)
            result
        }
        // 4. The coordinator collects the signatures into the certificate and broadcasts it.
        val coordinatorFinalize = ChillDKG.coordinatorFinalize(coordinatorStep1.state, step2.map { it.certEqSignature }, threshold)
        assertTrue(coordinatorFinalize.fault.isOk)
        assertNotNull(coordinatorFinalize.thresholdPublicKey)
        assertEquals(n, coordinatorFinalize.publicShares.size)
        assertNotNull(coordinatorFinalize.recovery)
        // 5. Every participant verifies the certificate and computes its DKG output.
        val participantResults = (0 until n).map { i ->
            val result = ChillDKG.participantFinalize(step2[i].state, coordinatorFinalize.certificate, n, threshold)
            assertTrue(result.fault.isOk)
            assertNotNull(result.secretShare)
            result
        }
        // All participants and the coordinator agree on the DKG output.
        participantResults.forEach {
            assertEquals(coordinatorFinalize.thresholdPublicKey, it.thresholdPublicKey)
            assertEquals(coordinatorFinalize.publicShares, it.publicShares)
            assertEquals(coordinatorFinalize.recovery, it.recovery)
        }
        // Each public share is the public key of the corresponding secret share.
        participantResults.forEachIndexed { i, result ->
            assertEquals(result.publicShares[i], result.secretShare!!.publicKey())
        }
        return Pair(hostPublicKeys, Pair(participantResults, coordinatorFinalize))
    }

    @Test
    fun `distributed key generation`() {
        runDkg()
    }

    @Test
    fun `dkg output can sign with frost`() {
        val (_, results) = runDkg()
        val (participantResults, _) = results
        val thresholdPublicKey = participantResults[0].thresholdPublicKey!!
        val publicShares = participantResults[0].publicShares
        val msg = Random.nextBytes(32).byteVector32()

        // Use the DKG output for a FROST signing session with 2 of the 3 participants.
        val tweakCache = TweakCache.create(thresholdPublicKey)
        val signerIds = listOf(0u, 2u)
        val nonces = signerIds.map { id ->
            SecretNonce.generate(Random.nextBytes(32).byteVector32(), participantResults[id.toInt()].secretShare!!, publicShares[id.toInt()], tweakCache.tweakedPublicKey, msg, null)
        }
        val aggregatedNonce = IndividualNonce.aggregate(nonces.map { it.second }).right
        assertNotNull(aggregatedNonce)
        val session = Session.create(aggregatedNonce, signerIds, signerIds.map { publicShares[it.toInt()] }, 3, 2, tweakCache, msg)
        val partialSigs = signerIds.mapIndexed { i, id ->
            session.sign(nonces[i].first, participantResults[id.toInt()].secretShare!!, id).right!!
        }
        signerIds.forEachIndexed { i, id ->
            assertTrue(session.verify(partialSigs[i], nonces[i].second, publicShares[id.toInt()], i))
        }
        val aggregateSig = session.aggregateSigs(partialSigs).right
        assertNotNull(aggregateSig)
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggregateSig, tweakCache.tweakedPublicKey))
    }

    @Test
    fun `recover dkg output`() {
        val (hostPublicKeys, results) = runDkg()
        val (participantResults, coordinatorFinalize) = results
        val recovery = participantResults[0].recovery!!

        // Each participant can recover its secret share and the session's public data from the recovery data.
        hostSecretKeys.forEachIndexed { i, hostSecretKey ->
            val recovered = ChillDKG.participantRecover(hostSecretKey, recovery)
            assertTrue(recovered.fault.isOk)
            assertEquals(participantResults[i].secretShare, recovered.secretShare)
            assertEquals(participantResults[i].thresholdPublicKey, recovered.thresholdPublicKey)
            assertEquals(participantResults[i].publicShares, recovered.publicShares)
            assertEquals(hostPublicKeys, recovered.hostPublicKeys)
            assertEquals(3, recovered.nParticipants)
            assertEquals(2, recovered.threshold)
        }
        // A host secret key that does not belong to the session cannot recover anything.
        val outsider = ChillDKG.participantRecover(PrivateKey(ByteArray(32) { 0x66 }), recovery)
        assertEquals(ChilldkgFault.INVALID_INPUT, outsider.fault.code)
        assertNull(outsider.secretShare)

        // The coordinator can recover the public data, but has no secret share.
        val coordinatorRecovered = ChillDKG.coordinatorRecover(recovery)
        assertTrue(coordinatorRecovered.fault.isOk)
        assertNull(coordinatorRecovered.secretShare)
        assertEquals(coordinatorFinalize.thresholdPublicKey, coordinatorRecovered.thresholdPublicKey)
        assertEquals(coordinatorFinalize.publicShares, coordinatorRecovered.publicShares)
        assertEquals(3, coordinatorRecovered.nParticipants)
        assertEquals(2, coordinatorRecovered.threshold)
    }

    @Test
    fun `recovery acknowledgments`() {
        val (hostPublicKeys, results) = runDkg()
        val recovery = results.first[0].recovery!!
        val acks = hostSecretKeys.map { hostSecretKey ->
            ChillDKG.recoveryAckSign(hostSecretKey, hostPublicKeys, 2, recovery, ByteVector32(Random.nextBytes(32)))
        }
        assertTrue(ChillDKG.recoveryAcksVerify(hostPublicKeys, 2, recovery, acks).isOk)
        // An ack signed with the wrong key is rejected and blames the corresponding participant.
        val badAcks = acks.toMutableList().apply {
            this[1] = ChillDKG.recoveryAckSign(hostSecretKeys[2], hostPublicKeys, 2, recovery, ByteVector32(Random.nextBytes(32)))
        }
        val fault = ChillDKG.recoveryAcksVerify(hostPublicKeys, 2, recovery, badAcks)
        assertEquals(ChilldkgFault.FAULTY_PARTICIPANT, fault.code)
        assertEquals(1u, fault.participantIndex)
    }

    @Test
    fun `invalid inputs`() {
        val hostPublicKeys = hostSecretKeys.map { ChillDKG.hostPublicKey(it) }
        // All-zero randomness is rejected.
        assertFails { ChillDKG.participantStep1(hostSecretKeys[0], hostPublicKeys, 2, ByteVector32(ByteArray(32))) }
        // Invalid host secret keys are rejected.
        assertFails { ChillDKG.hostPublicKey(PrivateKey(ByteArray(32))) }
        // Threshold larger than the number of participants is rejected.
        assertFails { ChillDKG.sessionParamsHash(hostPublicKeys, 4) }
        // Duplicate host public keys are rejected.
        assertFails { ChillDKG.sessionParamsHash(listOf(hostPublicKeys[0], hostPublicKeys[0]), 2) }

        // Using the wrong host secret key in step2 is a fault, not an exception.
        val step1 = hostSecretKeys.mapIndexed { i, hostSecretKey ->
            ChillDKG.participantStep1(hostSecretKey, hostPublicKeys, 2, ByteVector32(Random.nextBytes(32)))
        }
        val coordinatorStep1 = ChillDKG.coordinatorStep1(step1.map { it.message }, hostPublicKeys, 2)
        assertTrue(coordinatorStep1.fault.isOk)
        val step2 = ChillDKG.participantStep2(hostSecretKeys[1], step1[0].state, coordinatorStep1.message, ByteVector32(Random.nextBytes(32)))
        assertEquals(ChilldkgFault.INVALID_INPUT, step2.fault.code)

        // A tampered coordinator message is detected.
        val tamperedMessage = coordinatorStep1.message.toByteArray().apply { this[10] = (this[10] + 1).toByte() }.byteVector()
        val step2Tampered = ChillDKG.participantStep2(hostSecretKeys[0], step1[0].state, tamperedMessage, ByteVector32(Random.nextBytes(32)))
        assertFalse(step2Tampered.fault.isOk)
    }
}
