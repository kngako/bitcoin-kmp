package fr.acinq.bitcoin.crypto.dkg.chill

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.ChilldkgFault
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * Tests based on the reference test vectors of the ChillDKG BIP draft
 * (https://github.com/bitcoin/bips/pull/2227, vectors at bip-chilldkg/vectors/).
 *
 * Note: the vectors from https://github.com/siv2r/bip-frost-dkg are stale: they were generated with an older
 * version of the draft, which used the "BIP DKG/params_id" hash tag (renamed to "BIP DKG/params_hash") and computed
 * the TapTweak of the DKG output over the compressed encoding of the threshold public key (fixed to use BIP 341's
 * x-only serialization). The vectors used here match the current draft.
 *
 * The vectors are stateless by design: session states are re-derived by replaying the previous protocol steps with
 * the provided randomness (and the replayed messages are checked byte-for-byte, which also validates the previous
 * steps).
 *
 * Error handling differs between the reference (typed exceptions) and our API (fault codes for protocol faults,
 * exceptions for invalid local inputs), so error cases are checked as follows: if the call raises, the test passes
 * (our API validates some inputs, such as message sizes, upfront); a successful result is never acceptable; and
 * when the reference expects a protocol fault (a faulty participant or coordinator), a returned fault report must
 * have the expected code and blamed participant.
 */
class ChillDKGVectorsTestsCommon {
    private fun JsonObject.hexOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.hexList(key: String): List<String> = this[key]!!.jsonArray.map { it.jsonPrimitive.content }

    private fun JsonObject.intList(key: String): List<Int> = this[key]!!.jsonArray.map { it.jsonPrimitive.int }

    private fun JsonObject.params(key: String = "params"): Pair<List<PublicKey>, Int> {
        val params = this[key]!!.jsonObject
        return Pair(params.jsonObject.hexList("hostpubkeys").map { PublicKey.fromHex(it) }, params.jsonObject["t"]!!.jsonPrimitive.int)
    }

    /** Unlike [ByteVector32.fromValidHex], reject inputs that are not exactly 32 bytes (ByteVector32 silently truncates oversized inputs). */
    private fun byteVector32Exact(hex: String): ByteVector32 {
        val bytes = Hex.decode(hex)
        require(bytes.size == 32) { "expected 32 bytes" }
        return ByteVector32(bytes)
    }

    /** Map the reference's exception types to our fault codes; returns null for plain invalid-input errors. */
    private fun expectedFaultCode(type: String): Int? = when (type) {
        "FaultyCoordinatorError" -> ChilldkgFault.FAULTY_COORDINATOR
        "FaultyParticipantError" -> ChilldkgFault.FAULTY_PARTICIPANT
        "FaultyParticipantOrCoordinatorError" -> ChilldkgFault.FAULTY_PARTICIPANT_OR_COORDINATOR
        "UnknownFaultyParticipantOrCoordinatorError" -> ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR
        else -> null
    }

    /**
     * Run [action] for an error test case and check its outcome against the expected error:
     * - an exception is always acceptable (our API validates some inputs upfront instead of reporting a fault),
     * - a successful result is never acceptable,
     * - when the reference expects a protocol fault, a returned fault must have the expected code and blamed
     *   participant.
     */
    private fun assertError(testCase: JsonObject, action: () -> ChilldkgFault) {
        val expected = testCase["expectedError"]!!.jsonObject
        val expectedCode = expectedFaultCode(expected["type"]!!.jsonPrimitive.content)
        val expectedParticipant = (expected["participantId"] as? JsonPrimitive)?.intOrNull
        val fault = try {
            action()
        } catch (_: Throwable) {
            null
        }
        assertFalse(fault?.isOk == true, "case ${testCase["tcId"]!!} should fail: ${testCase["comment"]!!.jsonPrimitive.content}")
        if (fault != null && expectedCode != null) {
            assertEquals(expectedCode, fault.code, "case ${testCase["tcId"]!!}: ${testCase["comment"]!!.jsonPrimitive.content}")
            expectedParticipant?.let { assertEquals(it.toUInt(), fault.participantIndex, "case ${testCase["tcId"]!!}: ${testCase["comment"]!!.jsonPrimitive.content}") }
        }
    }

    @Test
    fun `hostpubkey gen`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/hostpubkey_gen_vectors.json")
        tests.jsonObject["validTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            assertEquals(PublicKey.fromHex(testCase["expectedHostpubkey"]!!.jsonPrimitive.content), ChillDKG.hostPublicKey(PrivateKey.fromHex(testCase["hostseckey"]!!.jsonPrimitive.content)), "case ${testCase["tcId"]!!}")
        }
        tests.jsonObject["errorTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            assertFails { ChillDKG.hostPublicKey(PrivateKey.fromHex(testCase["hostseckey"]!!.jsonPrimitive.content)) }
        }
    }

    @Test
    fun `params hash`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/params_hash_vectors.json")
        tests.jsonObject["validTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            val (hostPublicKeys, threshold) = testCase.params()
            assertEquals(ByteVector32.fromValidHex(testCase["expectedParamsHash"]!!.jsonPrimitive.content), ChillDKG.sessionParamsHash(hostPublicKeys, threshold), "case ${testCase["tcId"]!!}")
        }
        tests.jsonObject["errorTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            assertFails {
                val (hostPublicKeys, threshold) = testCase.params()
                ChillDKG.sessionParamsHash(hostPublicKeys, threshold)
            }
        }
    }

    @Test
    fun `participant step1`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/participant_step1_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                val (hostPublicKeys, threshold) = testCase.params()
                val result = ChillDKG.participantStep1(PrivateKey.fromHex(testCase["hostseckey"]!!.jsonPrimitive.content), hostPublicKeys, threshold, byteVector32Exact(testCase["random"]!!.jsonPrimitive.content))
                assertEquals(ByteVector(testCase["expectedPmsg1"]!!.jsonPrimitive.content), result.message, "case ${testCase["tcId"]!!}")
            }
            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                assertFails {
                    val (hostPublicKeys, threshold) = testCase.params()
                    ChillDKG.participantStep1(PrivateKey.fromHex(testCase["hostseckey"]!!.jsonPrimitive.content), hostPublicKeys, threshold, byteVector32Exact(testCase["random"]!!.jsonPrimitive.content))
                }
            }
        }
    }

    @Test
    fun `coordinator step1`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/coordinator_step1_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val pmsg1Pool = group.hexList("pmsg1Pool").map { ByteVector(it) }
            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                val (hostPublicKeys, threshold) = testCase.params()
                val result = ChillDKG.coordinatorStep1(testCase.intList("pmsg1Indices").map { i -> pmsg1Pool[i] }, hostPublicKeys, threshold)
                assertTrue(result.fault.isOk, "case ${testCase["tcId"]!!}")
                assertEquals(ByteVector(testCase["expectedCmsg1"]!!.jsonPrimitive.content), result.message, "case ${testCase["tcId"]!!}")
            }
            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                assertError(testCase) {
                    val (hostPublicKeys, threshold) = testCase.params()
                    ChillDKG.coordinatorStep1(testCase.intList("pmsg1Indices").map { i -> pmsg1Pool[i] }, hostPublicKeys, threshold).fault
                }
            }
        }
    }

    @Test
    fun `participant step2`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/participant_step2_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val (hostPublicKeys, threshold) = group.params()
            val hostSecretKey = PrivateKey.fromHex(group["hostseckey"]!!.jsonPrimitive.content)
            val random = byteVector32Exact(group["random"]!!.jsonPrimitive.content)
            val auxRand = byteVector32Exact(group["auxRand"]!!.jsonPrimitive.content)
            // Harness setup: re-derive the state from the prior round (also validates our step1 implementation).
            val step1 = ChillDKG.participantStep1(hostSecretKey, hostPublicKeys, threshold, random)
            assertEquals(ByteVector(group["pmsg1"]!!.jsonPrimitive.content), step1.message)

            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                val result = ChillDKG.participantStep2(hostSecretKey, step1.state, ByteVector(testCase["cmsg1"]!!.jsonPrimitive.content), auxRand)
                assertTrue(result.fault.isOk, "case ${testCase["tcId"]!!}")
                assertEquals(ByteVector64.fromValidHex(testCase["expectedPmsg2"]!!.jsonPrimitive.content), result.certEqSignature, "case ${testCase["tcId"]!!}")
            }
            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                assertError(testCase) {
                    // Error cases may override the host secret key, randomness or aux randomness.
                    val caseHostSecretKey = testCase.hexOrNull("hostseckey")?.let { hex -> PrivateKey.fromHex(hex) } ?: hostSecretKey
                    val caseRandom = testCase.hexOrNull("random")?.let { hex -> byteVector32Exact(hex) } ?: random
                    val caseAuxRand = testCase.hexOrNull("auxRand")?.let { hex -> byteVector32Exact(hex) } ?: auxRand
                    val state = if (caseHostSecretKey == hostSecretKey && caseRandom == random) step1.state else ChillDKG.participantStep1(caseHostSecretKey, hostPublicKeys, threshold, caseRandom).state
                    ChillDKG.participantStep2(caseHostSecretKey, state, ByteVector(testCase["cmsg1"]!!.jsonPrimitive.content), caseAuxRand).fault
                }
            }
        }
    }

    @Test
    fun `coordinator finalize`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/coordinator_finalize_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val (hostPublicKeys, threshold) = group.params()
            // Harness setup: re-derive the coordinator's state from the prior round (also validates our step1).
            val step1 = ChillDKG.coordinatorStep1(group.hexList("pmsgs1").map { ByteVector(it) }, hostPublicKeys, threshold)
            assertTrue(step1.fault.isOk)
            assertEquals(ByteVector(group["cmsg1"]!!.jsonPrimitive.content), step1.message)
            val pmsg2Pool = group.hexList("pmsg2Pool")

            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                val result = ChillDKG.coordinatorFinalize(step1.state, testCase.intList("pmsg2Indices").map { i -> ByteVector64.fromValidHex(pmsg2Pool[i]) }, threshold)
                assertTrue(result.fault.isOk, "case ${testCase["tcId"]!!}")
                val expected = testCase["expectedOutput"]!!.jsonObject
                assertEquals(ByteVector(expected["cmsg2"]!!.jsonPrimitive.content), result.certificate, "case ${testCase["tcId"]!!}")
                val dkgOutput = expected["dkgOutput"]!!.jsonObject
                assertEquals(PublicKey.fromHex(dkgOutput["threshPk"]!!.jsonPrimitive.content), result.thresholdPublicKey, "case ${testCase["tcId"]!!}")
                assertEquals(dkgOutput.jsonObject.hexList("pubshares").map { share -> PublicKey.fromHex(share) }, result.publicShares, "case ${testCase["tcId"]!!}")
                assertEquals(ByteVector(expected["recoveryData"]!!.jsonPrimitive.content), result.recovery, "case ${testCase["tcId"]!!}")
            }
            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                assertError(testCase) {
                    ChillDKG.coordinatorFinalize(step1.state, testCase.intList("pmsg2Indices").map { i -> ByteVector64.fromValidHex(pmsg2Pool[i]) }, threshold).fault
                }
            }
        }
    }

    @Test
    fun `participant finalize`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/participant_finalize_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val (hostPublicKeys, threshold) = group.params()
            val hostSecretKey = PrivateKey.fromHex(group["hostseckey"]!!.jsonPrimitive.content)
            // Harness setup: re-derive the state through the two prior rounds (also validates our step1 and step2).
            val step1 = ChillDKG.participantStep1(hostSecretKey, hostPublicKeys, threshold, byteVector32Exact(group["random"]!!.jsonPrimitive.content))
            assertEquals(ByteVector(group["pmsg1"]!!.jsonPrimitive.content), step1.message)
            val step2 = ChillDKG.participantStep2(hostSecretKey, step1.state, ByteVector(group["cmsg1"]!!.jsonPrimitive.content), byteVector32Exact(group["auxRand"]!!.jsonPrimitive.content))
            assertTrue(step2.fault.isOk)
            assertEquals(ByteVector64.fromValidHex(group["pmsg2"]!!.jsonPrimitive.content), step2.certEqSignature)

            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                val result = ChillDKG.participantFinalize(step2.state, ByteVector(testCase["cmsg2"]!!.jsonPrimitive.content), hostPublicKeys.size, threshold)
                assertTrue(result.fault.isOk, "case ${testCase["tcId"]!!}")
                val expected = testCase["expectedOutput"]!!.jsonObject
                val dkgOutput = expected["dkgOutput"]!!.jsonObject
                assertEquals(PrivateKey.fromHex(dkgOutput["secshare"]!!.jsonPrimitive.content), result.secretShare, "case ${testCase["tcId"]!!}")
                assertEquals(PublicKey.fromHex(dkgOutput["threshPk"]!!.jsonPrimitive.content), result.thresholdPublicKey, "case ${testCase["tcId"]!!}")
                assertEquals(dkgOutput.jsonObject.hexList("pubshares").map { share -> PublicKey.fromHex(share) }, result.publicShares, "case ${testCase["tcId"]!!}")
                assertEquals(ByteVector(expected["recoveryData"]!!.jsonPrimitive.content), result.recovery, "case ${testCase["tcId"]!!}")
            }
            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                assertError(testCase) {
                    ChillDKG.participantFinalize(step2.state, ByteVector(testCase["cmsg2"]!!.jsonPrimitive.content), hostPublicKeys.size, threshold).fault
                }
            }
        }
    }

    @Test
    fun `recover`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/recover_vectors.json")
        tests.jsonObject["validTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            // A null host secret key means recovery is performed as the coordinator.
            val result = when (val hostSecretKey = testCase.hexOrNull("hostseckey")) {
                null -> ChillDKG.coordinatorRecover(ByteVector(testCase["recoveryData"]!!.jsonPrimitive.content))
                else -> ChillDKG.participantRecover(PrivateKey.fromHex(hostSecretKey), ByteVector(testCase["recoveryData"]!!.jsonPrimitive.content))
            }
            assertTrue(result.fault.isOk, "case ${testCase["tcId"]!!}")
            val expected = testCase["expectedOutput"]!!.jsonObject
            val dkgOutput = expected["dkgOutput"]!!.jsonObject
            assertEquals((dkgOutput["secshare"] as? JsonPrimitive)?.contentOrNull?.let { hex -> PrivateKey.fromHex(hex) }, result.secretShare, "case ${testCase["tcId"]!!}")
            assertEquals(PublicKey.fromHex(dkgOutput["threshPk"]!!.jsonPrimitive.content), result.thresholdPublicKey, "case ${testCase["tcId"]!!}")
            assertEquals(dkgOutput.jsonObject.hexList("pubshares").map { share -> PublicKey.fromHex(share) }, result.publicShares, "case ${testCase["tcId"]!!}")
            val params = expected["params"]!!.jsonObject
            assertEquals(params.jsonObject.hexList("hostpubkeys").map { hostpubkey -> PublicKey.fromHex(hostpubkey) }, result.hostPublicKeys, "case ${testCase["tcId"]!!}")
            assertEquals(params.jsonObject["t"]!!.jsonPrimitive.int, result.threshold, "case ${testCase["tcId"]!!}")
        }
        tests.jsonObject["errorTestCases"]!!.jsonArray.forEach {
            val testCase = it.jsonObject
            assertError(testCase) {
                when (val hostSecretKey = testCase.hexOrNull("hostseckey")) {
                    null -> ChillDKG.coordinatorRecover(ByteVector(testCase["recoveryData"]!!.jsonPrimitive.content)).fault
                    else -> ChillDKG.participantRecover(PrivateKey.fromHex(hostSecretKey), ByteVector(testCase["recoveryData"]!!.jsonPrimitive.content)).fault
                }
            }
        }
    }

    @Test
    fun `coordinator investigate`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/coordinator_investigate_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val (hostPublicKeys, threshold) = group.params()
            val pmsgs1 = group.hexList("pmsgs1").map { ByteVector(it) }
            group["validTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                // The reference generates all investigation messages at once, whereas our API generates them one
                // participant at a time.
                val expectedMessages = testCase.hexList("expectedCinvMsgs")
                expectedMessages.forEachIndexed { participantId, expected ->
                    val (fault, message) = ChillDKG.coordinatorInvestigate(pmsgs1, hostPublicKeys, threshold, participantId.toUInt())
                    assertTrue(fault.isOk, "case ${testCase["tcId"]!!}")
                    assertEquals(ByteVector(expected), message, "case ${testCase["tcId"]!!}, participant $participantId")
                }
            }
        }
    }

    @Test
    fun `participant investigate`() {
        val tests = TestHelpers.readResourceAsJson("chilldkg/participant_investigate_vectors.json")
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val (hostPublicKeys, threshold) = group.params()
            val hostSecretKey = PrivateKey.fromHex(group["hostseckey"]!!.jsonPrimitive.content)
            val auxRand = byteVector32Exact(group["auxRand"]!!.jsonPrimitive.content)
            val cmsg1Pool = group.hexList("cmsg1Pool")
            // Harness setup: re-derive the state from the prior round (also validates our step1 implementation).
            val step1 = ChillDKG.participantStep1(hostSecretKey, hostPublicKeys, threshold, byteVector32Exact(group["random"]!!.jsonPrimitive.content))
            assertEquals(ByteVector(group["pmsg1"]!!.jsonPrimitive.content), step1.message)

            group["errorTestCases"]!!.jsonArray.forEach {
                val testCase = it.jsonObject
                // The participant's step2 must fail with an unknown faulty party, providing investigation data.
                val step2 = ChillDKG.participantStep2(hostSecretKey, step1.state, ByteVector(cmsg1Pool[testCase["cmsg1Index"]!!.jsonPrimitive.int]), auxRand)
                assertEquals(ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR, step2.fault.code, "case ${testCase["tcId"]!!}")
                assertNotNull(step2.investigationData, "case ${testCase["tcId"]!!}")
                // The investigation narrows down the faulty party.
                val fault = ChillDKG.participantInvestigate(step2.investigationData, ByteVector(testCase["cinvMsg"]!!.jsonPrimitive.content))
                val expected = testCase["expectedError"]!!.jsonObject
                assertEquals(expectedFaultCode(expected["type"]!!.jsonPrimitive.content), fault.code, "case ${testCase["tcId"]!!}: ${testCase["comment"]!!.jsonPrimitive.content}")
                (expected["participantId"] as? JsonPrimitive)?.intOrNull?.let { participant ->
                    assertEquals(participant.toUInt(), fault.participantIndex, "case ${testCase["tcId"]!!}: ${testCase["comment"]!!.jsonPrimitive.content}")
                }
            }
        }
    }
}
