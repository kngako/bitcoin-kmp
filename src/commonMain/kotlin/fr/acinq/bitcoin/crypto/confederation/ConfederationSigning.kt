@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.ScriptTree
import fr.acinq.bitcoin.SigHash
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.jvm.JvmStatic

/**
 * One signing attempt's session (protocol section 8.1): the key state, the selection, the tweaks and the session
 * id, and the D_sign they encode. Public, and recomputable: every party builds it itself with [create], and a signer
 * compares the coordinator's D_sign with its own ([check]) before it reveals a nonce.
 */
public class ConfederationSigningSession private constructor(
    public val keyState: ConfederationKeyState,
    public val sessionId: ByteVector32,
    public val selection: ConfederationSignerSelection,
    public val tweaks: List<ConfederationTweak>,
    internal val native: ByteArray,
    /** The canonical D_sign this session encodes. */
    public val dSign: ByteVector,
) {
    /** The selected signers, in the flattened order every per-signer list follows. */
    public val signers: List<ConfederationRoleId> = selection.signers

    /** The selected groups, in the order group partials follow. */
    public val groups: List<UInt> = selection.groups.keys.sorted()

    internal val sizes: fr.acinq.secp256k1.ConfederationSignMessageSizes = Secp256k1.confederationSignMessageSizes(native)

    /** True if [coordinatorDSign] is exactly the D_sign this session encodes. A signer generates no nonce otherwise. */
    public fun check(coordinatorDSign: ByteVector): Boolean =
        Secp256k1.confederationSignSessionCheck(native, keyState.roster.native, keyState.native, coordinatorDSign.toByteArray())

    override fun toString(): String = "ConfederationSigningSession(sessionId=$sessionId, signers=$signers, ${tweaks.size} tweaks)"

    public companion object {
        /** Build the session for [selection] signing under [keyState]'s key tweaked by [tweaks], in order. */
        @JvmStatic
        public fun create(
            keyState: ConfederationKeyState,
            sessionId: ByteVector32,
            selection: ConfederationSignerSelection,
            tweaks: List<ConfederationTweak>,
        ): Either<Throwable, ConfederationSigningSession> {
            val (groupIds, innerCounts, adminIds) = selection.encode(keyState.roster)
            val tweakSequence = ConfederationTweak.encode(tweaks)
            return try {
                val session = Secp256k1.confederationSignSessionInit(keyState.roster.native, keyState.native, sessionId.toByteArray(), groupIds, innerCounts, adminIds, tweakSequence)
                Either.Right(ConfederationSigningSession(keyState, sessionId, selection, tweaks, session.session, ByteVector(session.dSign)))
            } catch (t: Throwable) {
                Either.Left(t)
            }
        }
    }
}

/**
 * One signer's state in one attempt. It holds a secret nonce: it has no serializer and no copy, and it moves once
 * through issued, confirmed and spent. [ConfederationSigning.confirm] uses it once and [ConfederationSigning.sign]
 * spends it; any failure, and [abort], spends it too. A restart loses it, by design: the attempt is abandoned and the
 * next one takes a new session id. Never persist it: a restored nonce can reveal the share.
 */
@OptIn(ExperimentalAtomicApi::class)
public class ConfederationSigner private constructor(
    public val role: ConfederationRoleId,
    public val session: ConfederationSigningSession,
    /** The 66-byte public nonce, for the outer coordinator's transcript. */
    public val publicNonce: ByteVector,
    private val state: ByteArray,
) {
    private val stage = AtomicInt(ISSUED)

    /** True once this state can no longer confirm or sign. */
    public val isSpent: Boolean get() = stage.load() == SPENT

    /** Run [block] on the state if it is at [from], with no other call able to touch it meanwhile; then [to] on success, spent on failure. */
    internal fun <T> advance(from: Int, to: Int, what: String, block: (ByteArray) -> T): Either<Throwable, T> {
        if (!stage.compareAndSet(from, BUSY)) return Either.Left(IllegalStateException("this signer cannot $what: ${describe(stage.load())}"))
        return try {
            val result = block(state)
            stage.store(to)
            if (to == SPENT) state.fill(0)
            Either.Right(result)
        } catch (t: Throwable) {
            state.fill(0)
            stage.store(SPENT)
            Either.Left(t)
        }
    }

    /** Wipe the state: on timeout, restart or a superseded attempt. */
    public fun abort() {
        while (true) {
            val current = stage.load()
            if (current == SPENT) return
            if (current != BUSY && stage.compareAndSet(current, SPENT)) {
                Secp256k1.confederationSignerAbort(state)
                return
            }
        }
    }

    override fun toString(): String = "ConfederationSigner(role=$role, ${describe(stage.load())}, <secret>)"

    internal companion object {
        const val ISSUED = 0
        const val CONFIRMED = 1
        const val BUSY = 2
        const val SPENT = 3

        fun describe(stage: Int): String = when (stage) {
            ISSUED -> "not yet confirmed"
            CONFIRMED -> "already confirmed"
            BUSY -> "in use"
            else -> "spent"
        }

        fun issue(role: ConfederationRoleId, session: ConfederationSigningSession, publicNonce: ByteArray, state: ByteArray): ConfederationSigner =
            ConfederationSigner(role, session, ByteVector(publicNonce), state)
    }
}

/** Every selected signer's public nonce, in selection order (step 3). */
public data class ConfederationNonceTranscript(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** Every selected signer's confirmation of the transcript and message (step 5). */
public data class ConfederationConfirmationCertificate(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** One group's sum of its members' partials (step 7): the group id, then a 32-byte scalar. */
public data class ConfederationGroupPartial(val data: ByteVector) {
    init {
        require(data.size() == Secp256k1.CONFEDERATION_GROUP_PARTIAL_SIZE) { "a group partial is ${Secp256k1.CONFEDERATION_GROUP_PARTIAL_SIZE} bytes, got ${data.size()}" }
    }

    /** The group this partial is for. */
    public val groupId: UInt get() = data.toByteArray().let { ((it[0].toUInt() and 0xffu) shl 24) or ((it[1].toUInt() and 0xffu) shl 16) or ((it[2].toUInt() and 0xffu) shl 8) or (it[3].toUInt() and 0xffu) }

    public fun toByteArray(): ByteArray = data.toByteArray()
}

/**
 * Option A signing, one signer per device (protocol section 8):
 *
 *  1. every party:       [ConfederationSigningSession.create], and a signer [ConfederationSigningSession.check]s the coordinator's D_sign
 *  2. every signer:      [generateNonce]     -> its [ConfederationSigner] and public nonce
 *  3. outer coordinator: [transcript]
 *  4. every signer:      [confirm]           -> confirmation
 *  5. outer coordinator: [certificate]; anyone can [verifyCertificate]
 *  6. every signer:      [sign]              -> member partial
 *  7. group coordinator: [verifyMemberPartial], [aggregateGroup]
 *  8. outer coordinator: [verifyGroup], [aggregate] -> BIP 340 signature under the tweaked key
 *
 * Which selected admin coordinates a group, and which party coordinates the whole, is the application's choice.
 * Per-signer and per-group inputs are keyed by role or group id and ordered here; a missing or extra one is the
 * caller's error ([IllegalArgumentException]). [Either.Left] carries what the native library refused, and a misuse
 * of a [ConfederationSigner] (a second confirmation, a partial before confirmation, a second partial).
 *
 * WARNING: experimental research code, unaudited, not for production or for protecting value; see [Confederation].
 */
public object ConfederationSigning {
    private fun requireSize(what: String, actual: Int, expected: Int) = require(actual == expected) { "$what must be $expected bytes for this session, got $actual" }

    private fun <K, T> keyedBy(expected: List<K>, values: Map<K, T>, what: String): List<T> {
        require(values.keys == expected.toSet()) { "expected $what for exactly $expected, got ${values.keys}" }
        return expected.map { values.getValue(it) }
    }

    private fun ConfederationSigningSession.requireTranscript(transcript: ConfederationNonceTranscript) {
        requireSize("the nonce transcript", transcript.data.size(), sizes.nonceTranscript)
    }

    /**
     * Step 2, [role]: a fresh signer state and its public nonce. [randomness] must be fresh secret randomness, never
     * derived from public data. [share] must be [role]'s, bound to the session's key state.
     */
    @JvmStatic
    public fun generateNonce(
        session: ConfederationSigningSession,
        role: ConfederationRoleId,
        share: ConfederationShare,
        randomness: ByteVector32,
    ): Either<Throwable, ConfederationSigner> {
        require(role in session.signers) { "$role is not among the selected signers ${session.signers}" }
        require(share.role == role) { "the share belongs to ${share.role}, not $role" }
        val keyState = session.keyState
        val secrand = randomness.toByteArray()
        val state = ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE)
        return try {
            val publicNonce = Secp256k1.confederationSignerNonceGen(state, session.native, keyState.roster.native, keyState.native, share.native, session.dSign.toByteArray(), secrand)
            Either.Right(ConfederationSigner.issue(role, session, publicNonce, state))
        } catch (t: Throwable) {
            state.fill(0)
            Either.Left(t)
        } finally {
            secrand.fill(0)
        }
    }

    /** Step 3, outer coordinator: every signer's public nonce as one transcript. */
    @JvmStatic
    public fun transcript(session: ConfederationSigningSession, publicNonces: Map<ConfederationRoleId, ByteVector>): Either<Throwable, ConfederationNonceTranscript> {
        val ordered = keyedBy(session.signers, publicNonces, "a public nonce")
        ordered.forEach { requireSize("a public nonce", it.size(), 66) }
        return try {
            Either.Right(ConfederationNonceTranscript(ByteVector(Secp256k1.confederationNonceTranscriptWrite(session.native, ordered.map { it.toByteArray() }.toTypedArray()))))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }

    /**
     * Step 4, a signer: check the transcript holds its nonce and confirm it, with [message], under its host key. A
     * signer confirms once; a refusal spends it.
     */
    @JvmStatic
    public fun confirm(
        signer: ConfederationSigner,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        hostSecretKey: PrivateKey,
    ): Either<Throwable, ByteVector64> {
        val session = signer.session
        val keyState = session.keyState
        session.requireTranscript(transcript)
        val role = requireNotNull(keyState.roster.role(signer.role))
        require(hostSecretKey.publicKey() == role.hostPublicKey) { "the host secret key does not match ${signer.role}'s host public key" }
        val host = hostSecretKey.value.toByteArray()
        return try {
            signer.advance(ConfederationSigner.ISSUED, ConfederationSigner.CONFIRMED, "confirm") { state ->
                ByteVector64(Secp256k1.confederationSignerConfirm(state, session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), host))
            }
        } finally {
            host.fill(0)
        }
    }

    /** Step 5, outer coordinator: every signer's confirmation as one certificate. It does not verify them: [verifyCertificate] does. */
    @JvmStatic
    public fun certificate(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        confirmations: Map<ConfederationRoleId, ByteVector64>,
    ): Either<Throwable, ConfederationConfirmationCertificate> {
        session.requireTranscript(transcript)
        val ordered = keyedBy(session.signers, confirmations, "a confirmation")
        return try {
            val certificate = Secp256k1.confederationConfirmationCertificateWrite(session.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), ordered.map { it.toByteArray() }.toTypedArray())
            Either.Right(ConfederationConfirmationCertificate(ByteVector(certificate)))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }

    /** True if [certificate] holds every signer's valid confirmation of [transcript] and [message]. */
    @JvmStatic
    public fun verifyCertificate(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
    ): Boolean {
        val keyState = session.keyState
        return Secp256k1.confederationConfirmationVerify(session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray())
    }

    /**
     * Step 6, a signer: its 32-byte member partial, under a valid certificate for what it confirmed. This spends
     * the signer whatever happens. The partial may be cached and resent; it can never be computed again.
     */
    @JvmStatic
    public fun sign(
        signer: ConfederationSigner,
        share: ConfederationShare,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
    ): Either<Throwable, ByteVector32> {
        require(share.role == signer.role) { "the share belongs to ${share.role}, not ${signer.role}" }
        val session = signer.session
        val keyState = session.keyState
        session.requireTranscript(transcript)
        return signer.advance(ConfederationSigner.CONFIRMED, ConfederationSigner.SPENT, "sign") { state ->
            ByteVector32(Secp256k1.confederationSignerPartial(state, session.native, keyState.roster.native, keyState.native, share.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray()))
        }
    }

    /** Group coordinator: true if [partial] is [role]'s valid member partial. */
    @JvmStatic
    public fun verifyMemberPartial(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
        role: ConfederationRoleId,
        partial: ByteVector32,
    ): Boolean {
        val index = session.signers.indexOf(role)
        require(index >= 0) { "$role is not among the selected signers ${session.signers}" }
        val keyState = session.keyState
        return Secp256k1.confederationMemberPartialVerify(partial.toByteArray(), session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray(), index)
    }

    /** Step 7, group coordinator: [groupId]'s members' partials, each verified, summed into its group partial. */
    @JvmStatic
    public fun aggregateGroup(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
        groupId: UInt,
        partials: Map<ConfederationRoleId, ByteVector32>,
    ): Either<Throwable, ConfederationGroupPartial> {
        val outerIndex = session.groups.indexOf(groupId)
        require(outerIndex >= 0) { "group $groupId is not among the selected groups ${session.groups}" }
        val ordered = keyedBy(session.signers.filter { it.groupId == groupId }, partials, "a member partial")
        val keyState = session.keyState
        return try {
            val groupPartial = Secp256k1.confederationGroupPartialAggregate(
                session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray(),
                outerIndex, ordered.map { it.toByteArray() }.toTypedArray(),
            )
            Either.Right(ConfederationGroupPartial(ByteVector(groupPartial)))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }

    /** Outer coordinator: true if [groupPartial] is its group's valid partial. */
    @JvmStatic
    public fun verifyGroup(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
        groupPartial: ConfederationGroupPartial,
    ): Boolean {
        val outerIndex = session.groups.indexOf(groupPartial.groupId)
        if (outerIndex < 0) return false
        val keyState = session.keyState
        return Secp256k1.confederationGroupPartialVerify(groupPartial.toByteArray(), session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray(), outerIndex)
    }

    /** Step 8, outer coordinator: the BIP 340 signature, from every selected group's partial. It is verified before it is returned. */
    @JvmStatic
    public fun aggregate(
        session: ConfederationSigningSession,
        transcript: ConfederationNonceTranscript,
        message: ByteVector32,
        certificate: ConfederationConfirmationCertificate,
        groupPartials: Map<UInt, ConfederationGroupPartial>,
    ): Either<Throwable, ByteVector64> {
        val ordered = keyedBy(session.groups, groupPartials, "a group partial")
        ordered.zip(session.groups).forEach { (partial, groupId) -> require(partial.groupId == groupId) { "the partial given for group $groupId is group ${partial.groupId}'s" } }
        val keyState = session.keyState
        return try {
            val signature = Secp256k1.confederationOuterAggregate(
                session.native, keyState.roster.native, keyState.native, session.dSign.toByteArray(), transcript.toByteArray(), message.toByteArray(), certificate.toByteArray(),
                ordered.map { it.toByteArray() }.toTypedArray(),
            )
            Either.Right(ByteVector64(signature))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }

    /**
     * The session and message for signing the key path of taproot input [inputIndex] of [tx], whose output uses
     * [keyState]'s key as internal key with [scriptTree] (or no script path when null), with SIGHASH_DEFAULT. The
     * resulting signature goes in the witness as is. The step-by-step counterpart of [Confederation.signTaprootInputLocal].
     *
     * @param inputs the outputs spent by every input of [tx], in order.
     */
    @JvmStatic
    public fun taprootInputSession(
        keyState: ConfederationKeyState,
        sessionId: ByteVector32,
        selection: ConfederationSignerSelection,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        scriptTree: ScriptTree?,
    ): Either<Throwable, Pair<ConfederationSigningSession, ByteVector32>> {
        val tapTweak = scriptTree?.let { Crypto.TaprootTweak.ScriptPathTweak(it.hash()) } ?: Crypto.TaprootTweak.KeyPathTweak
        val message = Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, inputs, SigHash.SIGHASH_DEFAULT)
        return ConfederationSigningSession.create(keyState, sessionId, selection, listOf(ConfederationTweak.taproot(keyState.publicKey, tapTweak))).map { it to message }
    }
}
