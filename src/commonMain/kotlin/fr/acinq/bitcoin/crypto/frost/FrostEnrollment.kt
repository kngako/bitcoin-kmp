@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * Output of a helper's round 1.1 (see [FrostEnrollment.generateShares]).
 *
 * The shares are aligned with the helper ids the round was run with: the entry at this helper's own position is
 * kept locally and handed back to [FrostEnrollment.aggregateShares], and every other entry is sent to the helper
 * sitting at that position, together with [paramsHash].
 *
 * The shares are additive shares of a real secret share: they must be sent over confidential and authenticated
 * channels, and this API handles bytes only. The parameters hash is public.
 */
public data class EnrollmentShares(val shares: List<ByteVector32>, val paramsHash: ByteVector32) {
    init {
        require(shares.isNotEmpty()) { "enrollment shares must not be empty" }
    }

    override fun toString(): String = "<enrollment_shares>"
}

/**
 * Outcome of a helper's round 1.2 (see [FrostEnrollment.aggregateShares]).
 *
 * A helper disagreeing on the parameters is a normal protocol outcome that the caller must be able to attribute,
 * so it is reported here rather than as an error: only invalid arguments, which are a caller bug, come back as
 * [Either.Left].
 */
public sealed class ShareAggregation {
    /** The aggregated share to send to the target participant. Secret: it must be sent over a confidential and authenticated channel. */
    public data class Aggregated(val share: ByteVector32) : ShareAggregation() {
        override fun toString(): String = "<aggregated_enrollment_share>"
    }

    /**
     * A helper's contribution was at fault, either because its parameters hash disagreed with the recomputed one
     * or because its share was not a valid scalar. The two causes are deliberately not distinguished, so callers
     * must not report one of them specifically. Note that [helperId] can name the caller itself, since the share
     * it kept locally is summed along with the rest.
     *
     * @param helperId the identifier of the helper at fault, not its index in the helper ids.
     */
    public data class HelperAtFault(val helperId: UInt) : ShareAggregation()
}

/**
 * FROST enrollment: turning a (t, n) group into a (t, n+1) one, and repairing a participant's lost share, without
 * re-running key generation and without any helper revealing its secret share. The group's threshold public key
 * and every existing share are unchanged by an enrollment; only the number of participants grows.
 *
 * A run involves u helpers, which are existing participants with t <= u <= n, and one target identified by
 * `newId`. Passing `newId == nParticipants` enrolls a new participant; passing a smaller one reproduces that
 * existing participant's share exactly, which is the module's repair mode.
 *
 * The protocol runs in three rounds:
 * 1. round 1.1 ([generateShares]): each helper splits its Lagrange-scaled contribution into u additive shares, one
 *    per helper, and computes the parameters hash,
 * 2. round 1.2 ([aggregateShares]): the shares are TRANSPOSED - helper i's entry j travels to the helper at
 *    position j, which collects entry j from every helper - and each helper checks that everyone ran round 1.1 on
 *    the same parameters before summing its column into the single value it sends to the target,
 * 3. round 2 ([generateSecretShare]): the target sums the values received from the helpers and verifies the result
 *    against the public share it derives itself with [derivePublicShare].
 *
 * Every array of this API is aligned with the helper ids given to it, and the same ids in the same order must be
 * used across both rounds by all parties. The order does not change the parameters hash, which sorts them.
 *
 * PRECONDITION for the target, documented but not enforceable here: the threshold public key must come from a
 * source it authenticates independently of the helpers, and the expected public share must be derived from public
 * shares validated against that key (see [KeyMaterial.isValid]). Otherwise both round-2 checks are circular: t
 * colluding helpers can present a consistent but fabricated polynomial, and every check passes on a worthless
 * share.
 *
 * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in production.
 */
public object FrostEnrollment {
    /**
     * Compute the parameters hash that every party of an enrollment run computes for itself and compares against
     * the ones it receives. Binding the threshold public key makes the hash identify a group rather than a tuple of
     * numbers: two unrelated groups that happen to share (t, n, helperIds, newId) produce different hashes.
     *
     * This uses public data only, and enforces the same parameter constraints as every other function here, so it
     * is also the natural way to pre-validate a parameter tuple.
     *
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers, all distinct, all smaller than [nParticipants] and different
     * from [newId].
     * @param newId identifier of the participant receiving the share: [nParticipants] to enroll a new participant,
     * or smaller to repair the share of an existing one.
     * @param nParticipants total number of participants n, at most [Secp256k1.FROST_MAX_PARTICIPANTS] and strictly
     * smaller when enrolling.
     * @param threshold threshold t, at least 2 and at most [nParticipants].
     * @return the 32-byte parameters hash, or an error if the parameters are invalid.
     */
    @JvmStatic
    public fun paramsHash(thresholdPublicKey: PublicKey, helperIds: List<UInt>, newId: UInt, nParticipants: Int, threshold: Int): Either<Throwable, ByteVector32> = try {
        Either.Right(ByteVector32(Secp256k1.frostEnrollmentParamsHash(thresholdPublicKey.value.toByteArray(), helperIds.toUIntArray(), newId, nParticipants, threshold)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 1.1: generate a helper's enrollment shares, one per helper, plus the parameters hash to send along
     * with them (see [EnrollmentShares] for what goes where).
     *
     * The caller must guarantee that [sessionRandom] is fresh: reusing it across runs leaks share information, and
     * single use is not enforced at this layer (unlike [SecretNonce], which the library produces itself). Note that
     * the array is left untouched, following the convention of [Frost.generateNonce] and [Prefractal.partialSign].
     *
     * @param sessionRandom 32 bytes of fresh randomness, which must not be reused across runs.
     * @param secretShare this helper's own secret share.
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers, which fixes the alignment of the returned shares.
     * @param myId this helper's own identifier, which must be one of [helperIds].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the u shares aligned with [helperIds] and the parameters hash, or an error if the arguments are invalid.
     */
    @JvmStatic
    public fun generateShares(
        sessionRandom: ByteVector32,
        secretShare: PrivateKey,
        thresholdPublicKey: PublicKey,
        helperIds: List<UInt>,
        myId: UInt,
        newId: UInt,
        nParticipants: Int,
        threshold: Int
    ): Either<Throwable, EnrollmentShares> = try {
        val (shares, hash) = Secp256k1.frostEnrollmentSharesGen(
            sessionRandom.toByteArray(),
            secretShare.value.toByteArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            myId,
            newId,
            nParticipants,
            threshold
        )
        Either.Right(EnrollmentShares(shares.map { ByteVector32(it) }, ByteVector32(hash)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 1.2: check that every helper ran round 1.1 on the same parameters, and aggregate this helper's column
     * of shares into the single value to send to the target participant.
     *
     * The two lists are both aligned with [helperIds] but have deliberately opposite conventions for the caller's
     * own slot, which is what makes this a recomputation check rather than an equality test between strings the
     * caller supplied itself:
     *  - [shares]: the entry at [myId]'s position is read. It is the share [generateShares] kept locally.
     *  - [receivedParamsHashes]: the entry at [myId]'s position is never read and must be null. The own hash is
     *    always recomputed.
     *
     * @param shares u shares aligned with [helperIds]: the share kept locally at [myId]'s position, and the share
     * received from each other helper at theirs.
     * @param receivedParamsHashes u entries aligned with [helperIds], holding the parameters hash received from
     * each other helper, and null at [myId]'s own position.
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers, in the same order as in round 1.1.
     * @param myId this helper's own identifier, which must be one of [helperIds].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the aggregated share to send to the target, or the identifier of the helper at fault, or an error if
     * the arguments are invalid.
     */
    @JvmStatic
    public fun aggregateShares(
        shares: List<ByteVector32>,
        receivedParamsHashes: List<ByteVector32?>,
        thresholdPublicKey: PublicKey,
        helperIds: List<UInt>,
        myId: UInt,
        newId: UInt,
        nParticipants: Int,
        threshold: Int
    ): Either<Throwable, ShareAggregation> = try {
        // Only the caller's own slot may be left out: a null anywhere else would be sent to the C module as a zero
        // hash, which would come back as that helper being at fault, blaming it for the caller's own mistake.
        require(receivedParamsHashes.size == helperIds.size) { "parameters hashes count must match helper ids count" }
        helperIds.forEachIndexed { i, id ->
            require((receivedParamsHashes[i] == null) == (id == myId)) { "the parameters hash must be null at the caller's own position, and set at every other" }
        }
        val result = Secp256k1.frostEnrollmentShareAgg(
            shares.map { it.toByteArray() }.toTypedArray(),
            receivedParamsHashes.map { it?.toByteArray() ?: ByteArray(32) }.toTypedArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            myId,
            newId,
            nParticipants,
            threshold
        )
        when (val sigma = result.sigma) {
            null -> Either.Right(ShareAggregation.HelperAtFault(result.mismatchId!!))
            else -> Either.Right(ShareAggregation.Aggregated(ByteVector32(sigma)))
        }
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Derive the public share at the target identifier: the value of the group's public-share polynomial at the
     * target's x-coordinate. This is both the value round 2 verifies the new secret share against, and the entry
     * that extends the group's table of public shares from n to n+1 after an enrollment.
     *
     * This uses public data only, so any party can compute it.
     *
     * @param helperPublicShares public shares of the u helpers, aligned with [helperIds].
     * @param helperIds identifiers of the u helpers.
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the derived public share, or an error if the arguments are invalid.
     */
    @JvmStatic
    public fun derivePublicShare(helperPublicShares: List<PublicKey>, helperIds: List<UInt>, newId: UInt, nParticipants: Int, threshold: Int): Either<Throwable, PublicKey> = try {
        val pubshare = Secp256k1.frostEnrollmentPubshareDerive(
            helperPublicShares.map { it.value.toByteArray() }.toTypedArray(),
            helperIds.toUIntArray(),
            newId,
            nParticipants,
            threshold
        )
        Either.Right(PublicKey.parse(pubshare))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 2: derive the target participant's secret share from the values received from the helpers, checking
     * the parameters hash and verifying the result against the expected public share.
     *
     * [expectedPublicShare] is load-bearing: it is the only check that the helpers contributed correct values.
     * Pass null only if the resulting share is validated by other means, and see the precondition on
     * [FrostEnrollment] for why deriving it from unauthenticated data makes both checks circular.
     *
     * @param aggregatedShares the u values received from the helpers (see [aggregateShares]), aligned with [helperIds].
     * @param thresholdPublicKey the independently authenticated threshold public key of the group.
     * @param helperIds identifiers of the u helpers, in the same order as [aggregatedShares].
     * @param newId own identifier, the one the share is being derived for.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param expectedParamsHash the parameters hash received from the helpers, or null to skip the comparison.
     * @param expectedPublicShare the expected public share, from [derivePublicShare], or null to skip the
     * verification (not recommended).
     * @return the participant's secret share, or an error if a check fails or the arguments are invalid.
     */
    @JvmStatic
    public fun generateSecretShare(
        aggregatedShares: List<ByteVector32>,
        thresholdPublicKey: PublicKey,
        helperIds: List<UInt>,
        newId: UInt,
        nParticipants: Int,
        threshold: Int,
        expectedParamsHash: ByteVector32?,
        expectedPublicShare: PublicKey?
    ): Either<Throwable, PrivateKey> = try {
        val secshare = Secp256k1.frostEnrollmentSecshareGen(
            aggregatedShares.map { it.toByteArray() }.toTypedArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            newId,
            nParticipants,
            threshold,
            expectedParamsHash?.toByteArray(),
            expectedPublicShare?.value?.toByteArray()
        )
        Either.Right(PrivateKey(secshare))
    } catch (t: Throwable) {
        Either.Left(t)
    }
}
