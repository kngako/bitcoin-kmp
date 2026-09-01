package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * Tests based on the reference test vectors of the BIP-FROST signing specification
 * (https://github.com/siv2r/bip-frost-signing/tree/master/python/vectors).
 */
class FrostVectorsTestsCommon {
    /** Secret nonces in test vectors use a custom encoding. */
    private fun deserializeSecretNonce(hex: String): SecretNonce {
        val serialized = Hex.decode(hex)
        require(serialized.size == 64) { "secret nonce from test vector should be serialized using 64 bytes" }
        // In test vectors, secret nonces are serialized as: <scalar_1> <scalar_2>
        // We expect secret nonces serialized as: <magic> <scalar_1> <scalar_2>
        return SecretNonce(Hex.decode("5CCFB999") + serialized)
    }

    private fun JsonObject.hexOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.intList(key: String): List<Int> = this[key]!!.jsonArray.map { it.jsonPrimitive.int }

    private fun JsonObject.intListOrNull(key: String): List<Int>? = (this[key] as? JsonArray)?.map { it.jsonPrimitive.int }

    private fun JsonObject.booleanList(key: String): List<Boolean> = this[key]!!.jsonArray.map { it.jsonPrimitive.boolean }

    /** Apply the given tweaks, in order, to a tweak cache initialized from the threshold public key. */
    private fun tweakCache(thresholdPublicKey: PublicKey, tweaks: List<String>, isXonly: List<Boolean>): TweakCache {
        var cache = TweakCache.create(thresholdPublicKey)
        tweaks.forEachIndexed { i, tweak ->
            // NB: ByteVector32 silently truncates oversized inputs, so we must explicitly check the tweak's size.
            val tweakBytes = Hex.decode(tweak)
            require(tweakBytes.size == 32) { "tweak must be 32 bytes" }
            cache = cache.tweak(ByteVector32(tweakBytes), isXonly[i]).getOrElse { throw it }.first
        }
        return cache
    }

    @Test
    fun `generate secret nonce`() {
        val tests = TestHelpers.readResourceAsJson("frost/nonce_gen_vectors.json")
        tests.jsonObject["valid_tests"]!!.jsonArray.forEach { testCase0 ->
            val testCase = testCase0.jsonObject
            val (secretNonce, publicNonce) = SecretNonce.generate(
                sessionRandom = ByteVector32.fromValidHex(testCase["rand"]!!.jsonPrimitive.content),
                secretShare = testCase.hexOrNull("secshare")?.let { PrivateKey.fromHex(it) },
                publicShare = testCase.hexOrNull("pubshare")?.let { PublicKey.fromHex(it) },
                tweakedThresholdPublicKey = testCase.hexOrNull("thresh_pk_xonly")?.let { XonlyPublicKey(ByteVector32.fromValidHex(it)) },
                message = testCase.hexOrNull("msg")?.let { ByteVector(it) },
                extraInput = testCase.hexOrNull("extra_in")?.let { ByteVector32.fromValidHex(it) }
            )
            val expected = testCase["expected"]!!.jsonArray
            assertEquals(deserializeSecretNonce(expected[0].jsonPrimitive.content), secretNonce, "case ${testCase["tc_id"]!!}")
            assertEquals(IndividualNonce(expected[1].jsonPrimitive.content), publicNonce, "case ${testCase["tc_id"]!!}")
        }
    }

    @Test
    fun `aggregate nonces`() {
        val tests = TestHelpers.readResourceAsJson("frost/nonce_agg_vectors.json")
        val nonces = tests.jsonObject["pubnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        tests.jsonObject["valid_tests"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pubnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = AggregatedNonce(it.jsonObject["expected"]!!.jsonPrimitive.content)
            assertEquals(expected, IndividualNonce.aggregate(nonceIndices.map { i -> nonces[i] }).right, "case ${it.jsonObject["tc_id"]!!}")
        }
        tests.jsonObject["error_tests"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pubnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertTrue(IndividualNonce.aggregate(nonceIndices.map { i -> nonces[i] }).isLeft, "case ${it.jsonObject["tc_id"]!!} should fail")
        }
    }

    @Test
    fun `sign and verify`() {
        val tests = TestHelpers.readResourceAsJson("frost/sign_verify_vectors.json")
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val n = group["n"]!!.jsonPrimitive.int
            val t = group["t"]!!.jsonPrimitive.int
            val thresholdPublicKey = PublicKey.fromHex(group["thresh_pk"]!!.jsonPrimitive.content)
            val tweakCache = TweakCache.create(thresholdPublicKey)
            val publicShares = group["pubshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val publicNonces = group["pubnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
            val secretShares = group["secshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val secretNonces = group["secnonces"]!!.jsonArray.map { it.jsonPrimitive.content }

            group["valid_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val ids = testCase.intList("ids").map { it.toUInt() }
                val myId = testCase["my_id"]!!.jsonPrimitive.int.toUInt()
                val signerIndex = ids.indexOf(myId)
                val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                val session = Session.create(
                    AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                    ids,
                    signerPublicShares,
                    n,
                    t,
                    tweakCache,
                    ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                )
                val partialSig = session.sign(
                    deserializeSecretNonce(secretNonces[testCase["secnonce_index"]!!.jsonPrimitive.int]),
                    PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                    myId
                ).right
                assertEquals(ByteVector32.fromValidHex(testCase["expected"]!!.jsonPrimitive.content), partialSig, "case ${testCase["tc_id"]!!}")
                assertNotNull(partialSig)
                // The partial signature verifies against the signer's public share and public nonce.
                val publicNonceIndex = testCase.intList("pubnonce_indices")[signerIndex]
                assertTrue(session.verify(partialSig, publicNonces[publicNonceIndex], PublicKey.fromHex(publicShares[myId.toInt()]), signerIndex), "case ${testCase["tc_id"]!!}")
            }

            group["sign_error_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val result: Either<Throwable, ByteVector32> = try {
                    val ids = testCase.intList("ids").map { it.toUInt() }
                    val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                    val session = Session.create(
                        AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                        ids,
                        signerPublicShares,
                        n,
                        t,
                        tweakCache,
                        ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                    )
                    session.sign(
                        deserializeSecretNonce(secretNonces[testCase["secnonce_index"]!!.jsonPrimitive.int]),
                        PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                        testCase["my_id"]!!.jsonPrimitive.int.toUInt()
                    )
                } catch (e: Throwable) {
                    Either.Left(e)
                }
                assertTrue(result.isLeft, "case ${testCase["tc_id"]!!} should fail: ${testCase["comment"]!!.jsonPrimitive.content}")
            }

            listOf("verify_fail_tests", "verify_error_tests").forEach { kind ->
                group[kind]!!.jsonArray.forEach { testCase0 ->
                    val testCase = testCase0.jsonObject
                    // The reference distinguishes verification failures (return false) from verification errors
                    // (raise an exception), but our API intentionally collapses both into a false result.
                    val valid = try {
                        val ids = testCase.intList("ids").map { it.toUInt() }
                        val signerIndex = testCase["signer_index"]!!.jsonPrimitive.int
                        val publicNonceIndices = testCase.intList("pubnonce_indices")
                        val publicShareIndices = testCase.intList("pubshare_indices")
                        val aggregatedNonce = IndividualNonce.aggregate(publicNonceIndices.map { publicNonces[it] }).right!!
                        val session = Session.create(aggregatedNonce, ids, publicShareIndices.map { PublicKey.fromHex(publicShares[it]) }, n, t, tweakCache, ByteVector(testCase["msg"]!!.jsonPrimitive.content))
                        session.verify(ByteVector32.fromValidHex(testCase["psig"]!!.jsonPrimitive.content), publicNonces[publicNonceIndices[signerIndex]], PublicKey.fromHex(publicShares[publicShareIndices[signerIndex]]), signerIndex)
                    } catch (e: Throwable) {
                        false
                    }
                    assertFalse(valid, "case ${testCase["tc_id"]!!} should not verify: ${testCase["comment"]!!.jsonPrimitive.content}")
                }
            }
        }
    }

    @Test
    fun `sign with tweaks`() {
        val tests = TestHelpers.readResourceAsJson("frost/tweak_vectors.json")
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val n = group["n"]!!.jsonPrimitive.int
            val t = group["t"]!!.jsonPrimitive.int
            val thresholdPublicKey = PublicKey.fromHex(group["thresh_pk"]!!.jsonPrimitive.content)
            val publicShares = group["pubshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val secretShares = group["secshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val secretNonces = group["secnonces"]!!.jsonArray.map { it.jsonPrimitive.content }
            val tweaks = group["tweaks"]!!.jsonArray.map { it.jsonPrimitive.content }

            group["valid_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val ids = testCase.intList("ids").map { it.toUInt() }
                val myId = testCase["my_id"]!!.jsonPrimitive.int.toUInt()
                val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                val cache = tweakCache(thresholdPublicKey, testCase.intList("tweak_indices").map { tweaks[it] }, testCase.booleanList("is_xonly"))
                val session = Session.create(
                    AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                    ids,
                    signerPublicShares,
                    n,
                    t,
                    cache,
                    ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                )
                val partialSig = session.sign(
                    deserializeSecretNonce(secretNonces[testCase["secnonce_index"]!!.jsonPrimitive.int]),
                    PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                    myId
                ).right
                assertEquals(ByteVector32.fromValidHex(testCase["expected"]!!.jsonPrimitive.content), partialSig, "case ${testCase["tc_id"]!!}")
            }

            group["error_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val tweakIndices = testCase.intList("tweak_indices")
                val isXonly = testCase.booleanList("is_xonly")
                if (tweakIndices.size != isXonly.size) {
                    // Our API takes (tweak, isXonly) pairs, so a count mismatch is not expressible: nothing to test.
                    return@forEach
                }
                val result: Either<Throwable, ByteVector32> = try {
                    val cache = tweakCache(thresholdPublicKey, tweakIndices.map { tweaks[it] }, isXonly)
                    val ids = testCase.intList("ids").map { it.toUInt() }
                    val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                    val session = Session.create(
                        AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                        ids,
                        signerPublicShares,
                        n,
                        t,
                        cache,
                        ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                    )
                    session.sign(
                        deserializeSecretNonce(secretNonces[testCase["secnonce_index"]!!.jsonPrimitive.int]),
                        PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                        testCase["my_id"]!!.jsonPrimitive.int.toUInt()
                    )
                } catch (e: Throwable) {
                    Either.Left(e)
                }
                assertTrue(result.isLeft, "case ${testCase["tc_id"]!!} should fail: ${testCase["comment"]!!.jsonPrimitive.content}")
            }
        }
    }

    @Test
    fun `aggregate signatures`() {
        val tests = TestHelpers.readResourceAsJson("frost/sig_agg_vectors.json")
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val n = group["n"]!!.jsonPrimitive.int
            val t = group["t"]!!.jsonPrimitive.int
            val thresholdPublicKey = PublicKey.fromHex(group["thresh_pk"]!!.jsonPrimitive.content)
            val publicShares = group["pubshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val tweaks = group["tweaks"]!!.jsonArray.map { it.jsonPrimitive.content }

            group["valid_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val ids = testCase.intList("ids").map { it.toUInt() }
                val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                val cache = tweakCache(thresholdPublicKey, testCase.intList("tweak_indices").map { tweaks[it] }, testCase.booleanList("is_xonly"))
                val session = Session.create(
                    AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                    ids,
                    signerPublicShares,
                    n,
                    t,
                    cache,
                    ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                )
                val partialSigs = testCase["psigs"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
                val aggregateSig = session.aggregateSigs(partialSigs).right
                assertEquals(ByteVector64.fromValidHex(testCase["expected"]!!.jsonPrimitive.content), aggregateSig, "case ${testCase["tc_id"]!!}")
            }

            group["error_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val result: Either<Throwable, ByteVector64> = try {
                    val cache = tweakCache(thresholdPublicKey, testCase.intList("tweak_indices").map { tweaks[it] }, testCase.booleanList("is_xonly"))
                    val ids = testCase.intList("ids").map { it.toUInt() }
                    val signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) }
                    val session = Session.create(
                        AggregatedNonce(testCase["aggnonce"]!!.jsonPrimitive.content),
                        ids,
                        signerPublicShares,
                        n,
                        t,
                        cache,
                        ByteVector(testCase["msg"]!!.jsonPrimitive.content)
                    )
                    session.aggregateSigs(testCase["psigs"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) })
                } catch (e: Throwable) {
                    Either.Left(e)
                }
                assertTrue(result.isLeft, "case ${testCase["tc_id"]!!} should fail: ${testCase["comment"]!!.jsonPrimitive.content}")
            }
        }
    }

    @Test
    fun `deterministic sign`() {
        val tests = TestHelpers.readResourceAsJson("frost/det_sign_vectors.json")
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { group0 ->
            val group = group0.jsonObject
            val n = group["n"]!!.jsonPrimitive.int
            val t = group["t"]!!.jsonPrimitive.int
            val thresholdPublicKey = PublicKey.fromHex(group["thresh_pk"]!!.jsonPrimitive.content)
            val publicShares = group["pubshares"]!!.jsonArray.map { it.jsonPrimitive.content }
            val secretShares = group["secshares"]!!.jsonArray.map { it.jsonPrimitive.content }

            group["valid_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val result = Frost.deterministicSign(
                    secretShare = PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                    myId = testCase["my_id"]!!.jsonPrimitive.int.toUInt(),
                    aggregateOtherNonce = testCase.hexOrNull("aggothernonce")?.let { AggregatedNonce(it) },
                    signerIds = testCase.intList("ids").map { it.toUInt() },
                    signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) },
                    nParticipants = n,
                    threshold = t,
                    tweakCache = tweakCache(thresholdPublicKey, testCase["tweaks"]!!.jsonArray.map { it.jsonPrimitive.content }, testCase.booleanList("is_xonly")),
                    message = ByteVector(testCase["msg"]!!.jsonPrimitive.content),
                    auxRand = testCase.hexOrNull("aux_rand")?.let { ByteVector32.fromValidHex(it) }
                )
                val (partialSig, publicNonce) = result.right!!
                val expected = testCase["expected"]!!.jsonArray
                // NB: in test vectors, the expected pair is [pubnonce, psig].
                assertEquals(IndividualNonce(expected[0].jsonPrimitive.content), publicNonce, "case ${testCase["tc_id"]!!}")
                assertEquals(ByteVector32.fromValidHex(expected[1].jsonPrimitive.content), partialSig, "case ${testCase["tc_id"]!!}")
            }

            group["error_tests"]!!.jsonArray.forEach { testCase0 ->
                val testCase = testCase0.jsonObject
                val result: Either<Throwable, Pair<ByteVector32, IndividualNonce>> = try {
                    Frost.deterministicSign(
                        secretShare = PrivateKey.fromHex(secretShares[testCase["secshare_index"]!!.jsonPrimitive.int]),
                        myId = testCase["my_id"]!!.jsonPrimitive.int.toUInt(),
                        aggregateOtherNonce = testCase.hexOrNull("aggothernonce")?.let { AggregatedNonce(it) },
                        signerIds = testCase.intList("ids").map { it.toUInt() },
                        signerPublicShares = testCase.intListOrNull("pubshare_indices")?.map { PublicKey.fromHex(publicShares[it]) },
                        nParticipants = n,
                        threshold = t,
                        tweakCache = tweakCache(thresholdPublicKey, testCase["tweaks"]!!.jsonArray.map { it.jsonPrimitive.content }, testCase.booleanList("is_xonly")),
                        message = ByteVector(testCase["msg"]!!.jsonPrimitive.content),
                        auxRand = testCase.hexOrNull("aux_rand")?.let { ByteVector32.fromValidHex(it) }
                    )
                } catch (e: Throwable) {
                    Either.Left(e)
                }
                assertTrue(result.isLeft, "case ${testCase["tc_id"]!!} should fail: ${testCase["comment"]!!.jsonPrimitive.content}")
            }
        }
    }
}
