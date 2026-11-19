package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/** A dealer's zero-sharing polynomial commitments and its evaluations for every participant. */
public data class RefreshShares(
    val evaluations: List<PrivateKey>,
    val commitments: List<PublicKey>,
    val paramsHash: ByteVector32,
) {
    init {
        require(evaluations.isNotEmpty()) { "refresh evaluations must not be empty" }
        require(commitments.isNotEmpty()) { "refresh commitments must not be empty" }
    }

    override fun toString(): String = "<refresh_shares>"
}

/** A verified candidate for the next share epoch. */
public data class RefreshCandidate(
    val secretShare: PrivateKey,
    val publicShares: List<PublicKey>,
    val paramsHash: ByteVector32,
) {
    override fun toString(): String = "<refresh_candidate>"
}

/** Identifies the dealer whose evaluation did not match its public commitments. */
public class RefreshDealerFault(public val dealerId: UInt) :
    IllegalStateException("dealer $dealerId produced an invalid refresh evaluation")

/**
 * Proactive FROST share refresh: replace every participant's share without changing the threshold public key.
 *
 * Each participant deals a polynomial of degree `threshold - 1` whose constant term is zero. Participant `j`
 * adds the evaluations it receives to its existing share. The updated public shares are derived independently
 * from the existing public shares and the dealers' coefficient commitments.
 *
 * This is not [FrostEnrollment]: enrollment extends the existing polynomial or reproduces an existing share,
 * whereas refresh moves the group to a different polynomial with the same constant term. A refresh does not
 * revoke an old threshold quorum: anyone retaining `threshold` shares from one old epoch can still sign for
 * the unchanged group key. Honest participants must delete their old shares after activating the new epoch.
 *
 * Secret scalar arithmetic and point operations are performed by secp256k1 on every platform. This API handles
 * bytes and keys only; evaluations must be carried over confidential, authenticated channels by the caller.
 */
public object FrostRefresh {
    private const val PARAMS_TAG = "FROST refresh/params_hash"
    private const val RANDOM_TAG = "FROST refresh/random"
    private const val COEFFICIENT_TAG = "FROST refresh/coefficient"

    private data class Params(
        val sessionId: ByteVector32,
        val thresholdPublicKey: PublicKey,
        val currentEpoch: Long,
        val nextEpoch: Long,
        val participantIds: List<UInt>,
        val threshold: Int,
    ) {
        init {
            val n = participantIds.size
            require(n >= 2 && n <= Secp256k1.FROST_MAX_PARTICIPANTS) { "invalid participant count" }
            require(threshold in 2..n) { "refresh requires a threshold of at least two" }
            require(currentEpoch >= 0 && nextEpoch == currentEpoch + 1) { "share epochs must be consecutive" }
            require(participantIds.toSet().size == n) { "participant ids must be distinct" }
            require(participantIds.all { it < n.toUInt() }) { "participant ids must cover 0 until n" }
            require(thresholdPublicKey.isValid()) { "invalid threshold public key" }
        }

        val hash: ByteVector32 get() = paramsHash(this)
    }

    private fun taggedHash(tag: String, input: ByteArray): ByteArray {
        val tagHash = Crypto.sha256(tag.encodeToByteArray())
        return Crypto.sha256(tagHash + tagHash + input)
    }

    private fun u32(value: UInt): ByteArray = byteArrayOf(
        (value shr 24).toByte(),
        (value shr 16).toByte(),
        (value shr 8).toByte(),
        value.toByte(),
    )

    private fun u64(value: Long): ByteArray = ByteArray(8) { index ->
        (value ushr (56 - 8 * index)).toByte()
    }

    private fun paramsHash(params: Params): ByteVector32 {
        val sortedIds = params.participantIds.sorted()
        val input = params.sessionId.toByteArray() +
            params.thresholdPublicKey.value.toByteArray() +
            u64(params.currentEpoch) + u64(params.nextEpoch) +
            u32(params.participantIds.size.toUInt()) + u32(params.threshold.toUInt()) +
            sortedIds.fold(ByteArray(0)) { bytes, id -> bytes + u32(id) }
        return ByteVector32(taggedHash(PARAMS_TAG, input))
    }

    /** Compute the public hash that binds a refresh to its session, group, epochs and participant set. */
    @JvmStatic
    public fun paramsHash(
        sessionId: ByteVector32,
        thresholdPublicKey: PublicKey,
        currentEpoch: Long,
        nextEpoch: Long,
        participantIds: List<UInt>,
        threshold: Int,
    ): Either<Throwable, ByteVector32> = try {
        Either.Right(Params(sessionId, thresholdPublicKey, currentEpoch, nextEpoch, participantIds, threshold).hash)
    } catch (t: Throwable) {
        Either.Left(t)
    }

    private fun randomScalar(rand: ByteArray, paramsHash: ByteVector32, dealerId: UInt, coefficient: UInt): PrivateKey {
        var attempt = 0u
        while (true) {
            val input = rand + paramsHash.toByteArray() + u32(dealerId) + u32(coefficient) + u32(attempt)
            val candidate = PrivateKey(taggedHash(COEFFICIENT_TAG, input))
            if (candidate.isValid()) return candidate
            attempt++
        }
    }

    private fun xCoordinate(id: UInt): PrivateKey {
        val x = PrivateKey(u32(id + 1u).let { bytes -> ByteArray(28) + bytes })
        check(x.isValid()) { "participant id has no valid x-coordinate" }
        return x
    }

    private fun evaluateSecret(coefficients: List<PrivateKey>, id: UInt): PrivateKey {
        val x = xCoordinate(id)
        var power = x
        var result = coefficients[0] * power
        for (index in 1 until coefficients.size) {
            power *= x
            result += coefficients[index] * power
        }
        return result
    }

    private fun evaluatePublic(commitments: List<PublicKey>, id: UInt): PublicKey {
        val x = xCoordinate(id)
        var power = x
        var result = commitments[0] * power
        for (index in 1 until commitments.size) {
            power *= x
            result += commitments[index] * power
        }
        return result
    }

    /**
     * Generate one dealer's evaluations and commitments.
     *
     * The evaluations align with [participantIds]. Entry `j` is secret and must be sent only to that
     * participant. The commitments are the `threshold - 1` public coefficients, ordered by increasing degree.
     * [secretShare] is used only to mask the derived randomness against a broken random source.
     *
     * The caller must provide fresh [sessionRandom] for every new refresh session. Recomputing the same session
     * from the same inputs is deterministic, which permits safe redelivery. A new session requires new randomness.
     */
    @JvmStatic
    public fun generateShares(
        sessionRandom: ByteVector32,
        secretShare: PrivateKey,
        sessionId: ByteVector32,
        thresholdPublicKey: PublicKey,
        currentEpoch: Long,
        nextEpoch: Long,
        participantIds: List<UInt>,
        dealerId: UInt,
        threshold: Int,
    ): Either<Throwable, RefreshShares> = try {
        val params = Params(sessionId, thresholdPublicKey, currentEpoch, nextEpoch, participantIds, threshold)
        require(dealerId in participantIds) { "dealer must be a participant" }
        require(secretShare.isValid()) { "invalid current secret share" }

        val random = taggedHash(RANDOM_TAG, sessionRandom.toByteArray()).mapIndexed { index, byte ->
            (byte.toInt() xor secretShare.value[index].toInt()).toByte()
        }.toByteArray()
        val coefficients = (1 until threshold).map { coefficient ->
            randomScalar(random, params.hash, dealerId, coefficient.toUInt())
        }
        val evaluations = participantIds.map { id -> evaluateSecret(coefficients, id) }
        require(evaluations.all { it.isValid() }) { "dealer produced an unusable zero evaluation; use fresh randomness" }
        Either.Right(RefreshShares(evaluations, coefficients.map { it.publicKey() }, params.hash))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    private fun derivePublicShares(
        oldPublicShares: List<PublicKey>,
        commitments: List<List<PublicKey>>,
        params: Params,
    ): List<PublicKey> {
        require(oldPublicShares.size == params.participantIds.size) { "old public shares count must match participants" }
        require(commitments.size == params.participantIds.size) { "commitment sets count must match participants" }
        require(oldPublicShares.all { it.isValid() }) { "invalid old public share" }
        require(
            Secp256k1.frostThresholdInfoValidate(
                params.thresholdPublicKey.value.toByteArray(),
                oldPublicShares.map { it.value.toByteArray() }.toTypedArray(),
                params.threshold,
            )
        ) { "old public shares do not match the threshold public key" }

        commitments.forEachIndexed { dealerIndex, dealerCommitments ->
            require(dealerCommitments.size == params.threshold - 1) {
                "dealer ${params.participantIds[dealerIndex]} has the wrong commitment count"
            }
            if (!dealerCommitments.all { it.isValid() }) {
                throw RefreshDealerFault(params.participantIds[dealerIndex])
            }
        }

        val updated = params.participantIds.mapIndexed { recipientIndex, recipientId ->
            var publicShare = oldPublicShares[recipientIndex]
            commitments.forEach { dealerCommitments ->
                publicShare += evaluatePublic(dealerCommitments, recipientId)
            }
            publicShare
        }
        require(
            Secp256k1.frostThresholdInfoValidate(
                params.thresholdPublicKey.value.toByteArray(),
                updated.map { it.value.toByteArray() }.toTypedArray(),
                params.threshold,
            )
        ) { "candidate public shares do not match the threshold public key" }
        return updated
    }

    /** Derive and validate the candidate public-share table without handling any secret evaluations. */
    @JvmStatic
    public fun derivePublicShares(
        oldPublicShares: List<PublicKey>,
        commitments: List<List<PublicKey>>,
        sessionId: ByteVector32,
        thresholdPublicKey: PublicKey,
        currentEpoch: Long,
        nextEpoch: Long,
        participantIds: List<UInt>,
        threshold: Int,
    ): Either<Throwable, List<PublicKey>> = try {
        val params = Params(sessionId, thresholdPublicKey, currentEpoch, nextEpoch, participantIds, threshold)
        Either.Right(derivePublicShares(oldPublicShares, commitments, params))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Verify every dealer's evaluation for [recipientId], then add them to the current secret share.
     *
     * [evaluations] and [commitments] are aligned with [participantIds], and contain one evaluation per dealer
     * for this recipient. The expected candidate public share is derived internally rather than trusted from the
     * dealers. A bad evaluation returns [RefreshDealerFault] naming its dealer. No candidate is returned when any
     * evaluation or the complete candidate public-share table is invalid.
     */
    @JvmStatic
    public fun generateCandidate(
        oldSecretShare: PrivateKey,
        oldPublicShares: List<PublicKey>,
        evaluations: List<PrivateKey>,
        commitments: List<List<PublicKey>>,
        recipientId: UInt,
        sessionId: ByteVector32,
        thresholdPublicKey: PublicKey,
        currentEpoch: Long,
        nextEpoch: Long,
        participantIds: List<UInt>,
        threshold: Int,
    ): Either<Throwable, RefreshCandidate> = try {
        val params = Params(sessionId, thresholdPublicKey, currentEpoch, nextEpoch, participantIds, threshold)
        val recipientIndex = participantIds.indexOf(recipientId)
        require(recipientIndex >= 0) { "recipient must be a participant" }
        require(oldSecretShare.isValid()) { "invalid current secret share" }
        require(evaluations.size == participantIds.size) { "evaluations count must match participants" }

        var candidate = oldSecretShare
        evaluations.forEachIndexed { dealerIndex, evaluation ->
            val dealerId = participantIds[dealerIndex]
            val valid = evaluation.isValid() && runCatching {
                evaluation.publicKey() == evaluatePublic(commitments[dealerIndex], recipientId)
            }.getOrDefault(false)
            if (!valid) throw RefreshDealerFault(dealerId)
            candidate += evaluation
        }
        val candidatePublicShares = derivePublicShares(oldPublicShares, commitments, params)
        require(candidate.isValid()) { "candidate secret share must not be zero" }
        require(candidate.publicKey() == candidatePublicShares[recipientIndex]) {
            "candidate secret share does not match its public share"
        }
        Either.Right(RefreshCandidate(candidate, candidatePublicShares, params.hash))
    } catch (t: Throwable) {
        Either.Left(t)
    }
}
