@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.ChilldkgFault
import fr.acinq.secp256k1.FrostRefreshShape
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * The validated, serialized parameters of one refresh session: what every party must agree on, and what every
 * step of [FrostRefresh] takes. Contains no secret.
 */
public class FrostRefreshParams private constructor(
    /** The serialization the native module parses; see secp256k1_frost_refresh_params_serialize. */
    public val data: ByteVector,
    public val nParticipants: Int,
    public val threshold: Int,
    /** The generation being refreshed: 0 is ChillDKG's output. */
    public val generation: UInt,
    /** The recipients' identifiers, ascending. Every other participant is withheld. */
    public val recipientIds: List<UInt>,
) {
    /** The participants dealt nothing by this refresh, ascending. */
    public val withheldIds: List<UInt> get() = (0 until nParticipants).map { it.toUInt() }.filter { it !in recipientIds }

    override fun equals(other: Any?): Boolean = other is FrostRefreshParams && other.data == data
    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "FrostRefreshParams(n=$nParticipants, t=$threshold, generation=$generation, recipients=$recipientIds)"

    public companion object {
        /** Parameters from their serialization, or null if it is not one. The native code validates them in full. */
        @JvmStatic
        public fun fromData(data: ByteVector): FrostRefreshParams? {
            val shape = FrostRefreshShape.of(data.toByteArray()) ?: return null
            if (data.size() != shape.serializedLen) return null
            return FrostRefreshParams(data, shape.nParticipants, shape.threshold, shape.generation, shape.recipientIds)
        }
    }
}

/**
 * A fault, attributed to a participant IDENTIFIER. The native module reports a position in the recipient list,
 * which this wrapper translates, so that a caller can never blame the participant sitting at the wrong place.
 */
public data class FrostRefreshFault(val code: Int, val participantId: UInt?) {
    val isOk: Boolean get() = code == ChilldkgFault.OK

    internal companion object {
        fun of(fault: ChilldkgFault, params: FrostRefreshParams?): FrostRefreshFault =
            FrostRefreshFault(fault.code, fault.participantIndex?.let { pos -> params?.recipientIds?.getOrNull(pos.toInt()) })
    }
}

/** Result of [FrostRefresh.coordinatorStep1]: the message to broadcast to every recipient (cmsg1), or a fault. */
public data class RefreshCoordinatorStep1Result(val fault: FrostRefreshFault, val message: ByteVector?)

/** Result of [FrostRefresh.participantStep2]. On fault every output is null. */
public data class RefreshParticipantStep2Result(
    val fault: FrostRefreshFault,
    /** This recipient's share of the new generation. Secret. Store it before sending [certEqSignature]. */
    val newSecretShare: PrivateKey?,
    /** Every participant's public share at the new generation, withheld ones included, by identifier. */
    val newPublicShares: List<PublicKey>?,
    /** The confirmation to send to the coordinator (pmsg2): "I hold the new generation". */
    val certEqSignature: ByteVector64?,
) {
    override fun toString(): String = "RefreshParticipantStep2Result(fault=$fault, newSecretShare=${if (newSecretShare == null) "null" else "<secret>"})"
}

/** Result of [FrostRefresh.coordinatorFinalize] (the certificate) and [FrostRefresh.participantFinalize] (the recovery data). */
public data class RefreshFinalizeResult(val fault: FrostRefreshFault, val output: ByteVector?)

/** Result of [FrostRefresh.participantRecover]. */
public data class RefreshRecoverResult(val fault: FrostRefreshFault, val newSecretShare: PrivateKey?, val newPublicShares: List<PublicKey>?, val participantId: UInt?) {
    override fun toString(): String = "RefreshRecoverResult(fault=$fault, participantId=$participantId, newSecretShare=${if (newSecretShare == null) "null" else "<secret>"})"
}

/** Result of [FrostRefresh.publicRecover]. */
public data class RefreshPublicRecoverResult(val fault: FrostRefreshFault, val params: FrostRefreshParams?, val newPublicShares: List<PublicKey>?)

/**
 * FROST share refresh: give every recipient a new share of the SAME threshold key, on a new polynomial, so that
 * shares from before the refresh no longer combine with shares after it. The key, and everything signed with it,
 * stays as it is.
 *
 * Enrollment ([FrostEnrollment], [FrostReducedEnrollment]) cannot do this: it evaluates the existing polynomial,
 * and every old share is still one of its points. The two compose -- a participant withheld from a refresh is
 * brought back by a [FrostReducedEnrollment] repair at its identifier, against the new generation's public share.
 *
 * The run, with a fresh `refreshId`, recipients R (at least t, every one a dealer) and the authenticated public
 * shares of the generation being refreshed:
 * 1. [params] on every party, with identical arguments,
 * 2. [participantStep1] on every recipient; the messages go to the coordinator,
 * 3. [coordinatorStep1], whose message is broadcast to every recipient,
 * 4. [participantStep2] on every recipient: store the new share and table, THEN send the signature,
 * 5. [coordinatorFinalize] makes the certificate, and [participantFinalize] verifies it: only then does the group
 *    move to the new generation.
 *
 * Messages and signatures are taken keyed by participant identifier, and exactly the recipients must be present: a
 * missing or extra entry is the caller's error ([IllegalArgumentException]), never a participant at fault.
 *
 * WARNING: the underlying secp256k1-zkp frost_refresh module is experimental, has no BIP and no independent
 * review, and must not be used in production. A refresh protects against an adversary holding fewer than t shares
 * of any one generation, which requires every participant to delete its old share: t old shares still reconstruct
 * the key. And it does not survive a leaked host secret key, from which every generation can be recovered.
 */
public object FrostRefresh {
    /**
     * Validate the parameters of one refresh session.
     *
     * @param publicShares the n public shares of the generation being refreshed, by identifier. These must come
     * from authenticated group state: the module cannot check them against anything, and a wrong table every party
     * agrees on produces a consistent refresh of the wrong key material.
     */
    @JvmStatic
    public fun params(
        thresholdPublicKey: PublicKey,
        hostPublicKeys: List<PublicKey>,
        publicShares: List<PublicKey>,
        threshold: Int,
        generation: UInt,
        recipientIds: List<UInt>,
        refreshId: ByteVector32,
    ): Either<Throwable, FrostRefreshParams> = try {
        val data = Secp256k1.frostRefreshParamsSerialize(
            thresholdPublicKey.value.toByteArray(),
            hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(),
            publicShares.map { it.value.toByteArray() }.toTypedArray(),
            threshold,
            generation,
            recipientIds.toUIntArray(),
            refreshId.toByteArray(),
        )
        Either.Right(requireNotNull(FrostRefreshParams.fromData(ByteVector(data))))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /** The 32-byte parameters hash every message is bound to. */
    @JvmStatic
    public fun paramsHash(params: FrostRefreshParams): ByteVector32 = ByteVector32(Secp256k1.frostRefreshParamsHash(params.data.toByteArray()))

    /**
     * Round 1: a recipient deals its zero-constant polynomial. [random] must be fresh for every call.
     * @return the message for the coordinator, which holds no secret in the clear.
     */
    @JvmStatic
    public fun participantStep1(hostSecretKey: PrivateKey, params: FrostRefreshParams, participantId: UInt, random: ByteVector32): Either<Throwable, ByteVector> = try {
        require(participantId in params.recipientIds) { "participant $participantId is not a recipient" }
        Either.Right(ByteVector(Secp256k1.frostRefreshParticipantStep1(hostSecretKey.value.toByteArray(), params.data.toByteArray(), participantId, random.toByteArray())))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /** The coordinator sums the recipients' round-1 messages, keyed by identifier. */
    @JvmStatic
    public fun coordinatorStep1(messages: Map<UInt, ByteVector>, params: FrostRefreshParams): RefreshCoordinatorStep1Result {
        require(messages.keys == params.recipientIds.toSet()) { "expected a message from exactly the recipients ${params.recipientIds}, got ${messages.keys}" }
        val ordered = params.recipientIds.map { messages.getValue(it).toByteArray() }.toTypedArray()
        val result = Secp256k1.frostRefreshCoordinatorStep1(ordered, params.data.toByteArray())
        return RefreshCoordinatorStep1Result(FrostRefreshFault.of(result.fault, params), result.cmsg1?.let(::ByteVector))
    }

    /**
     * Round 2: a recipient checks what it was dealt, and computes its new share, the new public-share table and its
     * confirmation. The caller MUST store the share and table durably before sending the confirmation, and MUST NOT
     * sign with the share before [participantFinalize] verifies the certificate.
     *
     * A [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR] means what was dealt does not match the
     * commitments. There is no investigation procedure: the session must be abandoned.
     */
    @JvmStatic
    public fun participantStep2(
        hostSecretKey: PrivateKey,
        secretShare: PrivateKey,
        params: FrostRefreshParams,
        participantId: UInt,
        coordinatorMessage: ByteVector,
        auxRand: ByteVector32,
    ): RefreshParticipantStep2Result {
        val result = Secp256k1.frostRefreshParticipantStep2(
            hostSecretKey.value.toByteArray(),
            secretShare.value.toByteArray(),
            params.data.toByteArray(),
            participantId,
            coordinatorMessage.toByteArray(),
            auxRand.toByteArray(),
        )
        return RefreshParticipantStep2Result(
            FrostRefreshFault.of(result.fault, params),
            result.newSecshare?.let { PrivateKey(it) },
            result.newPubshares?.map { PublicKey(it) },
            result.sig64?.let { ByteVector64(it) },
        )
    }

    /** The coordinator verifies the confirmations, keyed by identifier, into the certificate. */
    @JvmStatic
    public fun coordinatorFinalize(params: FrostRefreshParams, coordinatorMessage: ByteVector, signatures: Map<UInt, ByteVector64>): RefreshFinalizeResult {
        require(signatures.keys == params.recipientIds.toSet()) { "expected a confirmation from exactly the recipients ${params.recipientIds}, got ${signatures.keys}" }
        val ordered = params.recipientIds.map { signatures.getValue(it).toByteArray() }.toTypedArray()
        val result = Secp256k1.frostRefreshCoordinatorFinalize(params.data.toByteArray(), coordinatorMessage.toByteArray(), ordered)
        return RefreshFinalizeResult(FrostRefreshFault.of(result.fault, params), result.output?.let(::ByteVector))
    }

    /**
     * Anyone verifies the certificate: on success every recipient has stored the new generation, and the group can
     * move to it. The output is the recovery data, which holds no secret in the clear.
     */
    @JvmStatic
    public fun participantFinalize(params: FrostRefreshParams, coordinatorMessage: ByteVector, certificate: ByteVector): RefreshFinalizeResult {
        val result = Secp256k1.frostRefreshParticipantFinalize(params.data.toByteArray(), coordinatorMessage.toByteArray(), certificate.toByteArray())
        return RefreshFinalizeResult(FrostRefreshFault.of(result.fault, params), result.output?.let(::ByteVector))
    }

    /**
     * A recipient rebuilds its new share from the recovery data, its host secret key and its share of the generation
     * that was refreshed. Chained from [fr.acinq.bitcoin.crypto.dkg.chill.ChillDKG.participantRecover], this
     * rebuilds any generation from the host secret key.
     */
    @JvmStatic
    public fun participantRecover(hostSecretKey: PrivateKey, secretShare: PrivateKey, recovery: ByteVector): RefreshRecoverResult {
        val result = Secp256k1.frostRefreshParticipantRecover(hostSecretKey.value.toByteArray(), secretShare.value.toByteArray(), recovery.toByteArray())
        return RefreshRecoverResult(
            FrostRefreshFault.of(result.fault, null),
            result.newSecshare?.let { PrivateKey(it) },
            result.newPubshares?.map { PublicKey(it) },
            result.participantId,
        )
    }

    /**
     * Anyone rebuilds the parameters and the new public-share table from certified recovery data: how a withheld
     * participant, or a device that took no part, learns the new generation's table.
     */
    @JvmStatic
    public fun publicRecover(recovery: ByteVector): RefreshPublicRecoverResult {
        val result = Secp256k1.frostRefreshPublicRecover(recovery.toByteArray())
        return RefreshPublicRecoverResult(
            FrostRefreshFault.of(result.fault, null),
            result.params?.let { FrostRefreshParams.fromData(ByteVector(it)) },
            result.newPubshares?.map { PublicKey(it) },
        )
    }
}
