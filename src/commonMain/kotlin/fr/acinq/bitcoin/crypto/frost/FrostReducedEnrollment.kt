@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * A secret value of a reduced enrollment run together with the parameters hash it was computed under: what a helper
 * sends to a larger-identifier helper after round 1.1, and what every helper sends to the target after round 1.2.
 *
 * [share] is an additive share of a real secret share: it must travel over a confidential and authenticated
 * channel. [paramsHash] is public.
 */
public data class ReducedEnrollmentMessage(val share: ByteVector32, val paramsHash: ByteVector32) {
    override fun toString(): String = "<reduced_enrollment_message>"
}

/**
 * Output of a helper's round 1.1 of reduced enrollment (see [FrostReducedEnrollment.generateShares]).
 *
 * Routing is by identifier, which is why this is not an aligned list like [EnrollmentShares]: [kept] stays with the
 * helper for its own round 1.2, every entry of [outgoing] is sent to the helper it is keyed by, and helpers with a
 * smaller identifier receive nothing from this one at all.
 */
public data class ReducedEnrollmentShares(val kept: ByteVector32, val outgoing: Map<UInt, ByteVector32>, val paramsHash: ByteVector32) {
    /** The message to send to helper [helperId], which must be a key of [outgoing]. */
    public fun messageFor(helperId: UInt): ReducedEnrollmentMessage =
        ReducedEnrollmentMessage(requireNotNull(outgoing[helperId]) { "no share for helper $helperId" }, paramsHash)

    override fun toString(): String = "<reduced_enrollment_shares>"
}

/**
 * Reduced (version 2) FROST enrollment: the same operation as [FrostEnrollment] - turning a (t, n) group into a
 * (t, n+1) one, or repairing a participant's lost share - with fewer messages and stricter binding. This is the
 * protocol new integrations should use.
 *
 * What changes from the full protocol:
 * - helper-to-helper shares form a triangle: a helper sends only to helpers with a larger identifier, u(u-1)/2
 *   messages in all instead of u(u-1),
 * - the parameters hash binds a [sessionId] chosen by the target, so messages from one run cannot be replayed into
 *   another run over the same group and parameters,
 * - the target's verification against the expected public share is mandatory.
 *
 * The two protocols must never be mixed within a run, and their parameters hashes differ by construction. They are
 * kept apart here as separate objects with separate message types, so a mix is a type error rather than a runtime
 * one.
 *
 * Unlike [FrostEnrollment], whose arrays are aligned with the helper ids, every function here that takes messages
 * from other helpers takes them keyed by the sender's identifier, and checks that exactly the expected senders are
 * present. A missing or extra entry is a caller error ([Either.Left]), never a helper at fault: blaming a helper for
 * a message the caller failed to route would be indistinguishable, to the group, from that helper misbehaving.
 *
 * The run:
 * 1. the target creates a fresh [sessionId]; every helper authorizes the exact session, group, n, t, target and
 *    helper set out of band,
 * 2. round 1.1 ([generateShares]): each helper keeps one share and sends one to every larger-identifier helper,
 * 3. round 1.2 ([aggregateShares]): each helper combines its kept share with those received from smaller-identifier
 *    helpers, and sends the result to the target,
 * 4. the expected public share comes from authenticated group state, through [FrostEnrollment.derivePublicShare] or
 *    [derivePublicShareFromCommitments],
 * 5. round 2 ([generateSecretShare]): the target combines one message from every helper and verifies the result.
 *
 * After an enrollment, every participant appends the same derived public share, moves n to n+1, validates the
 * extended table (see [KeyMaterial.isValid]) and persists the transition atomically before signing. A repair leaves
 * the group unchanged. Transport, deduplication, authorization, consensus and persistence are the caller's.
 *
 * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in production. In
 * particular, the generalized protocol with more helpers than the threshold requires independent review.
 */
public object FrostReducedEnrollment {
    /**
     * Compute the reduced-enrollment parameters hash. It commits to the reduced protocol, the threshold public key,
     * n, t, the target, the sorted helper set and [sessionId], so it is incompatible with
     * [FrostEnrollment.paramsHash] by design.
     *
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers, all distinct, all smaller than [nParticipants] and different
     * from [newId].
     * @param newId identifier of the participant receiving the share: [nParticipants] to enroll, smaller to repair.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t, at least 2 and at most [nParticipants].
     * @param sessionId identifies exactly one enrollment or repair request. Chosen fresh by the target and
     * authenticated by every helper; it need not be secret.
     * @return the 32-byte parameters hash, or an error if the parameters are invalid.
     */
    @JvmStatic
    public fun paramsHash(thresholdPublicKey: PublicKey, helperIds: List<UInt>, newId: UInt, nParticipants: Int, threshold: Int, sessionId: ByteVector32): Either<Throwable, ByteVector32> = try {
        Either.Right(ByteVector32(Secp256k1.frostEnrollmentReducedParamsHash(thresholdPublicKey.value.toByteArray(), helperIds.toUIntArray(), newId, nParticipants, threshold, sessionId.toByteArray())))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 1.1: generate this helper's row of the triangular share matrix.
     *
     * The caller must guarantee that [sessionRandom] is fresh: [sessionId] does not replace it, and reusing it
     * across runs leaks share information. As with [FrostEnrollment.generateShares], the array is left untouched.
     *
     * @param sessionRandom 32 bytes of fresh randomness, which must not be reused across runs.
     * @param secretShare this helper's own secret share.
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers.
     * @param myId this helper's own identifier, which must be one of [helperIds].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param sessionId the run's session identifier.
     * @return the share to keep, the shares to send keyed by recipient, and the parameters hash, or an error if
     * the arguments are invalid.
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
        threshold: Int,
        sessionId: ByteVector32
    ): Either<Throwable, ReducedEnrollmentShares> = try {
        val (shares, hash) = Secp256k1.frostEnrollmentReducedSharesGen(
            sessionRandom.toByteArray(),
            secretShare.value.toByteArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            myId,
            newId,
            nParticipants,
            threshold,
            sessionId.toByteArray()
        )
        // Routing follows the identifiers, never the values: an entry for a smaller identifier is structurally zero
        // and is dropped because of where it sits, not because it is zero.
        val kept = ByteVector32(shares[helperIds.indexOf(myId)])
        val outgoing = helperIds.withIndex().filter { (_, id) -> id > myId }.associate { (i, id) -> id to ByteVector32(shares[i]) }
        Either.Right(ReducedEnrollmentShares(kept, outgoing, ByteVector32(hash)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 1.2: check the parameters hash of every smaller-identifier helper against a fresh recomputation, and
     * combine this helper's column into the message to send to the target.
     *
     * @param kept the share [generateShares] kept for this helper.
     * @param received the message from every helper whose identifier is smaller than [myId], keyed by sender, and
     * from no other: exactly those keys must be present.
     * @param thresholdPublicKey threshold public key of the group.
     * @param helperIds identifiers of the u helpers.
     * @param myId this helper's own identifier, which must be one of [helperIds].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param sessionId the run's session identifier.
     * @return the message for the target, or the identifier of the helper at fault, or an error if the arguments
     * are invalid.
     */
    @JvmStatic
    public fun aggregateShares(
        kept: ByteVector32,
        received: Map<UInt, ReducedEnrollmentMessage>,
        thresholdPublicKey: PublicKey,
        helperIds: List<UInt>,
        myId: UInt,
        newId: UInt,
        nParticipants: Int,
        threshold: Int,
        sessionId: ByteVector32
    ): Either<Throwable, ReducedShareAggregation> = try {
        require(myId in helperIds) { "myId must be one of the helper ids" }
        val senders = helperIds.filter { it < myId }.toSet()
        require(received.keys == senders) { "expected a message from exactly the helpers with a smaller identifier: $senders, got ${received.keys}" }
        val zero = ByteArray(32)
        val shares = helperIds.map { id ->
            when {
                id == myId -> kept.toByteArray()
                id < myId -> received.getValue(id).share.toByteArray()
                else -> zero
            }
        }
        val hashes = helperIds.map { id -> received[id]?.paramsHash?.toByteArray() ?: zero }
        val result = Secp256k1.frostEnrollmentReducedShareAgg(
            shares.toTypedArray(),
            hashes.toTypedArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            myId,
            newId,
            nParticipants,
            threshold,
            sessionId.toByteArray()
        )
        when (val sigma = result.sigma) {
            null -> Either.Right(ReducedShareAggregation.HelperAtFault(result.mismatchId!!))
            // The hash sent on is this helper's own recomputation, so it is the one round 2 compares.
            else -> Either.Right(ReducedShareAggregation.Aggregated(ReducedEnrollmentMessage(ByteVector32(sigma), paramsHash(thresholdPublicKey, helperIds, newId, nParticipants, threshold, sessionId).right!!)))
        }
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Derive a public share from the group's aggregate VSS commitments, rather than from helper public shares as
     * [FrostEnrollment.derivePublicShare] does.
     *
     * AUTHENTICATION: this is arithmetic, not verification. [thresholdPublicKey] and [commitments] must come from
     * group state authenticated independently of the helpers; otherwise colluding helpers can supply a different
     * polynomial with the same constant term.
     *
     * @param thresholdPublicKey threshold public key of the group, which must equal the first commitment.
     * @param commitments the t commitments C[0], ..., C[t-1] in ascending coefficient order, null for the point at
     * infinity (a zero non-constant coefficient).
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @return the derived public share, or an error if the arguments are invalid.
     */
    @JvmStatic
    public fun derivePublicShareFromCommitments(thresholdPublicKey: PublicKey, commitments: List<PublicKey?>, newId: UInt, nParticipants: Int): Either<Throwable, PublicKey> = try {
        val pubshare = Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(
            thresholdPublicKey.value.toByteArray(),
            commitments.map { it?.value?.toByteArray() ?: ByteArray(33) }.toTypedArray(),
            newId,
            nParticipants
        )
        Either.Right(PublicKey.parse(pubshare))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Round 2: combine one message from every helper into the target's secret share, and verify it.
     *
     * Every parameters hash is checked against the one recomputed from the arguments, and the result is accepted
     * only if its public key is [expectedPublicShare], which is why that argument is not optional here.
     *
     * @param received the message from every helper, keyed by sender: exactly the keys of [helperIds].
     * @param thresholdPublicKey the independently authenticated threshold public key of the group.
     * @param helperIds identifiers of the u helpers.
     * @param newId own identifier, the one the share is being derived for.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param sessionId the run's session identifier, the one this target chose.
     * @param expectedPublicShare from authenticated group state, through [FrostEnrollment.derivePublicShare] or
     * [derivePublicShareFromCommitments].
     * @return the participant's verified secret share, or an error if a check fails or the arguments are invalid.
     */
    @JvmStatic
    public fun generateSecretShare(
        received: Map<UInt, ReducedEnrollmentMessage>,
        thresholdPublicKey: PublicKey,
        helperIds: List<UInt>,
        newId: UInt,
        nParticipants: Int,
        threshold: Int,
        sessionId: ByteVector32,
        expectedPublicShare: PublicKey
    ): Either<Throwable, PrivateKey> = try {
        require(received.keys == helperIds.toSet()) { "expected a message from exactly the helpers $helperIds, got ${received.keys}" }
        val secshare = Secp256k1.frostEnrollmentReducedSecshareGen(
            helperIds.map { received.getValue(it).share.toByteArray() }.toTypedArray(),
            helperIds.map { received.getValue(it).paramsHash.toByteArray() }.toTypedArray(),
            thresholdPublicKey.value.toByteArray(),
            helperIds.toUIntArray(),
            newId,
            nParticipants,
            threshold,
            sessionId.toByteArray(),
            expectedPublicShare.value.toByteArray()
        )
        Either.Right(PrivateKey(secshare))
    } catch (t: Throwable) {
        Either.Left(t)
    }
}

/**
 * Outcome of a helper's round 1.2 of reduced enrollment (see [FrostReducedEnrollment.aggregateShares]). As with
 * [ShareAggregation], a helper at fault is a protocol outcome to attribute, not an error.
 */
public sealed class ReducedShareAggregation {
    /** The message to send to the target participant. Secret: it must travel over a confidential and authenticated channel. */
    public data class Aggregated(val message: ReducedEnrollmentMessage) : ReducedShareAggregation()

    /**
     * A smaller-identifier helper's parameters hash disagreed with the recomputed one, or a share was not a valid
     * scalar. [helperId] is an identifier, not a position, and can name the caller itself, since its kept share is
     * summed along with the rest.
     */
    public data class HelperAtFault(val helperId: UInt) : ReducedShareAggregation()
}
