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
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * One role's secret share, bound to the roster and key state it was created or last rebound under. Secret.
 *
 * A share has no canonical encoding: persist it as a [ConfederationRecoveryPackage], which only its host secret key
 * opens, or keep its 32-byte scalar and [Confederation.wrapShare] it again. Neither layer can wipe the memory it
 * occupies.
 */
public class ConfederationShare internal constructor(
    public val role: ConfederationRoleId,
    internal val native: ByteArray,
) {
    /** True if this share is bound to [state] and matches its expected public share. */
    public fun isValidFor(state: ConfederationKeyState): Boolean = Secp256k1.confederationShareValidate(native, state.native, state.roster.native)

    /**
     * Rebind this share to [state], when the role is still in it and its scalar still matches its public share. The
     * scalar is unchanged; only its metadata moves. Authenticated by the role's host secret key.
     */
    public fun rebind(hostSecretKey: PrivateKey, state: ConfederationKeyState): Either<Throwable, ConfederationShare> = try {
        Either.Right(ConfederationShare(role, Secp256k1.confederationShareRebind(native, hostSecretKey.value.toByteArray(), state.native, state.roster.native)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    override fun toString(): String = "ConfederationShare(role=$role, <secret>)"
}

/**
 * A role's share, encrypted to its host key with the transition that created it (protocol section 13). [data] (269
 * bytes) may be stored or sent; opening it needs the host secret key. The encryption is a non-standard candidate
 * construction that has not been reviewed.
 */
public class ConfederationRecoveryPackage private constructor(
    /** The canonical 269-byte encoding. */
    public val data: ByteVector,
    internal val native: ByteArray,
) {
    /**
     * Decrypt this package and bind the share to [state], which must be the state that holds it: recovery from a
     * superseded polynomial, or for a role [state] no longer has, fails.
     */
    public fun open(hostSecretKey: PrivateKey, state: ConfederationKeyState): Either<Throwable, ConfederationShare> = try {
        val role = requireNotNull(state.roster.roleOf(hostSecretKey.publicKey())) { "no role in the roster has this host key" }
        Either.Right(ConfederationShare(role.id, Secp256k1.confederationRecoveryOpen(native, hostSecretKey.value.toByteArray(), state.native, state.roster.native)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    override fun equals(other: Any?): Boolean = other is ConfederationRecoveryPackage && other.data == data
    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "ConfederationRecoveryPackage(${data.size()} bytes)"

    public companion object {
        /** Parse and authenticate a 269-byte package. Does not need, or check against, any descriptor. */
        @JvmStatic
        public fun fromData(data: ByteVector, hostSecretKey: PrivateKey): Either<Throwable, ConfederationRecoveryPackage> = try {
            Either.Right(ConfederationRecoveryPackage(data, Secp256k1.confederationRecoveryParse(data.toByteArray(), hostSecretKey.value.toByteArray())))
        } catch (t: Throwable) {
            Either.Left(t)
        }

        internal fun fromNative(native: ByteArray): ConfederationRecoveryPackage =
            ConfederationRecoveryPackage(ByteVector(Secp256k1.confederationRecoverySerialize(native)), native)
    }
}

/**
 * One tweak of a signing session's key, applied in order (protocol section 8.1). [tweak] may be zero; [isXonly]
 * selects x-only (BIP 341) rather than plain tweaking.
 */
public data class ConfederationTweak(val tweak: ByteVector32, val isXonly: Boolean) {
    public companion object {
        /** At most this many tweaks fit a session (CONFEDERATION_TWEAK_SEQUENCE_MAX_SIZE = 4 + 64 * 33). */
        public const val MAX_COUNT: Int = 64

        /**
         * The BIP 341 tweak of [internalKey]: signing under a confederation key with this tweak produces a signature
         * under the P2TR output key `internalKey.outputKey(tapTweak)`.
         */
        @JvmStatic
        public fun taproot(internalKey: XonlyPublicKey, tapTweak: Crypto.TaprootTweak): ConfederationTweak = ConfederationTweak(internalKey.tweak(tapTweak), isXonly = true)

        /** `u32 count` followed by `scalar32 tweak || u8 is_xonly` per tweak. Four zero bytes for none. */
        internal fun encode(tweaks: List<ConfederationTweak>): ByteArray {
            require(tweaks.size <= MAX_COUNT) { "at most $MAX_COUNT tweaks, got ${tweaks.size}" }
            val out = ByteArray(4 + 33 * tweaks.size)
            val count = tweaks.size
            out[0] = (count ushr 24).toByte(); out[1] = (count ushr 16).toByte(); out[2] = (count ushr 8).toByte(); out[3] = count.toByte()
            tweaks.forEachIndexed { i, t ->
                val scalar = t.tweak.toByteArray()
                require(scalar.all { it == 0.toByte() } || Secp256k1.secKeyVerify(scalar)) { "tweak $i is not below the group order" }
                scalar.copyInto(out, 4 + 33 * i)
                out[4 + 33 * i + 32] = if (t.isXonly) 1 else 0
            }
            return out
        }
    }
}

/**
 * The signers of one attempt: for each selected outer group, the admins signing for it. Order does not matter; the
 * wrapper sorts both levels canonically.
 */
public data class ConfederationSignerSelection(val groups: Map<UInt, Set<UInt>>) {
    /** The selected roles, in flattened order. */
    public val signers: List<ConfederationRoleId> get() = groups.flatMap { (g, admins) -> admins.map { ConfederationRoleId(g, it) } }.sorted()

    /** Check against [roster] and encode as the native module's (groupIds, innerCounts, adminIds). */
    internal fun encode(roster: ConfederationRoster): Triple<UIntArray, IntArray, UIntArray> {
        require(groups.size >= roster.outerThreshold) { "${groups.size} groups selected, the roster requires ${roster.outerThreshold}" }
        val groupIds = groups.keys.sorted()
        groupIds.forEach { g ->
            val group = requireNotNull(roster.group(g)) { "group $g is not in the roster" }
            val admins = groups.getValue(g)
            require(admins.size >= group.threshold) { "${admins.size} admins selected in group $g, it requires ${group.threshold}" }
            admins.forEach { a -> require(group.roles.any { it.id.adminId == a }) { "admin $a is not in group $g" } }
        }
        return Triple(
            groupIds.toUIntArray(),
            groupIds.map { groups.getValue(it).size }.toIntArray(),
            groupIds.flatMap { groups.getValue(it).sorted() }.toUIntArray(),
        )
    }
}

/** Output of [Confederation.dkgLocal]. Holds every role's share: secret. */
public class ConfederationDkgOutput(
    public val keyState: ConfederationKeyState,
    public val genesis: ConfederationTransition,
    public val shares: Map<ConfederationRoleId, ConfederationShare>,
    public val recoveries: Map<ConfederationRoleId, ConfederationRecoveryPackage>,
) {
    override fun toString(): String = "ConfederationDkgOutput(keyState=$keyState, genesis=$genesis, ${shares.size} shares <secret>)"
}

/**
 * Confederation: nested threshold keys. A roster of outer groups, each with its own inner threshold of admins, holds
 * one BIP 340 key; T groups, each signing with at least t_g of its admins, produce a signature under it.
 *
 * Every per-role input is keyed by [ConfederationRoleId] and ordered here, in the roster's flattened order: a missing
 * or extra role, or a host key that is not the role's, is the caller's error ([IllegalArgumentException]), never a
 * [Either.Left].
 *
 * WARNING: the underlying secp256k1-zkp confederation module is experimental research code. It is not audited or
 * stable and must not be used in production or to protect value. In particular:
 * - [dkgLocal] and [signLocal] run EVERY role in one process, holding every host secret key and share. They are a
 *   simulation and test harness, not a distributed protocol: the round-by-round steps, and enrollment, refresh,
 *   masking and resharing, are not public at the pinned native revision.
 * - A transition certificate proves authorization, not consensus: see [ConfederationTransition].
 * - Unique host keys do not establish independent people or entities; [ConfederationRoster.access] is only as good
 *   as the roster's entity attestation.
 * - Compromising a host key exposes that role's shares in every epoch where the key was registered.
 * - Transport, sender authentication, durable attempt records, timeouts and atomic persistence are the
 *   application's.
 *
 * See the pinned header, protocol candidate and security notes at
 * https://code.sigidli.com/frost/secp256k1-zkp/src/commit/e18a8e8e5cba0e10860b7f3e6a8464f257ed9e61/include/secp256k1_confederation.h,
 * .../doc/confederation-protocol.md and .../src/modules/confederation/security.md.
 */
public object Confederation {
    private fun <T> keyedByRole(roster: ConfederationRoster, values: Map<ConfederationRoleId, T>, what: String): List<T> {
        require(values.keys == roster.roleIds.toSet()) { "expected $what for exactly the roles ${roster.roleIds}, got ${values.keys.sorted()}" }
        return roster.roleIds.map { values.getValue(it) }
    }

    private fun hostKeys(roster: ConfederationRoster, hostSecretKeys: Map<ConfederationRoleId, PrivateKey>): Array<ByteArray> {
        val ordered = keyedByRole(roster, hostSecretKeys, "a host secret key")
        roster.roles.zip(ordered).forEach { (role, key) -> require(key.publicKey() == role.hostPublicKey) { "the host secret key for ${role.id} does not match its host public key" } }
        return ordered.map { it.value.toByteArray() }.toTypedArray()
    }

    /**
     * Run the initial nested DKG for every role of [roster], in this process. [sessionSeed], and every dealer seed and
     * recovery nonce, must be fresh.
     *
     * The caller must then, atomically: check the genesis certificate against its own expectations, persist
     * `(configSeq, roster hash, key state hash)`, the canonical certificate and every role's recovery package.
     */
    @JvmStatic
    public fun dkgLocal(
        roster: ConfederationRoster,
        sessionSeed: ByteVector32,
        hostSecretKeys: Map<ConfederationRoleId, PrivateKey>,
        dealerSeeds: Map<ConfederationRoleId, ByteVector32>,
        recoveryNonces: Map<ConfederationRoleId, ByteVector32>,
    ): Either<Throwable, ConfederationDkgOutput> {
        val hosts = hostKeys(roster, hostSecretKeys)
        val dealers = keyedByRole(roster, dealerSeeds, "a dealer seed").map { it.toByteArray() }.toTypedArray()
        val nonces = keyedByRole(roster, recoveryNonces, "a recovery nonce").map { it.toByteArray() }.toTypedArray()
        return try {
            val result = Secp256k1.confederationDkg(roster.native, sessionSeed.toByteArray(), hosts, dealers, nonces)
            val keyState = ConfederationKeyState.fromNative(result.ksd, roster)
            Either.Right(
                ConfederationDkgOutput(
                    keyState,
                    ConfederationTransition.fromNative(result.transition, null, keyState),
                    roster.roleIds.zip(result.shares) { id, share -> id to ConfederationShare(id, share) }.toMap(),
                    roster.roleIds.zip(result.recoveries) { id, recovery -> id to ConfederationRecoveryPackage.fromNative(recovery) }.toMap(),
                )
            )
        } catch (t: Throwable) {
            Either.Left(t)
        } finally {
            hosts.forEach { it.fill(0) }
            dealers.forEach { it.fill(0) }
        }
    }

    /**
     * Run one complete signing attempt in this process, and return a BIP 340 signature of [message] under
     * [keyState]'s key tweaked by [tweaks] in order.
     *
     * The native module takes a share and host secret key for EVERY role of the roster, signers or not. Use a fresh
     * [signingSessionId] for every attempt, including a retry of a failed one.
     */
    @JvmStatic
    public fun signLocal(
        keyState: ConfederationKeyState,
        shares: Map<ConfederationRoleId, ConfederationShare>,
        hostSecretKeys: Map<ConfederationRoleId, PrivateKey>,
        selection: ConfederationSignerSelection,
        tweaks: List<ConfederationTweak>,
        signingSessionId: ByteVector32,
        message: ByteVector32,
    ): Either<Throwable, ByteVector64> {
        val roster = keyState.roster
        val orderedShares = keyedByRole(roster, shares, "a share")
        roster.roleIds.zip(orderedShares).forEach { (id, share) -> require(share.role == id) { "the share given for $id belongs to ${share.role}" } }
        val hosts = hostKeys(roster, hostSecretKeys)
        val (groupIds, innerCounts, adminIds) = selection.encode(roster)
        val tweakSequence = ConfederationTweak.encode(tweaks)
        return try {
            val sig = Secp256k1.confederationSign(
                roster.native, keyState.native,
                orderedShares.map { it.native }.toTypedArray(), hosts,
                signingSessionId.toByteArray(), groupIds, innerCounts, adminIds, tweakSequence, message.toByteArray(),
            )
            Either.Right(ByteVector64(sig))
        } catch (t: Throwable) {
            Either.Left(t)
        } finally {
            hosts.forEach { it.fill(0) }
        }
    }

    /**
     * Sign the key path of taproot input [inputIndex] of [tx], whose output uses [keyState]'s key as internal key with
     * [scriptTree] (or no script path when null), with SIGHASH_DEFAULT. The signature goes in the witness as is, with
     * [fr.acinq.bitcoin.Script.witnessKeyPathPay2tr]. Same single-process caveats as [signLocal].
     *
     * @param inputs the outputs spent by every input of [tx], in order.
     */
    @JvmStatic
    public fun signTaprootInputLocal(
        keyState: ConfederationKeyState,
        shares: Map<ConfederationRoleId, ConfederationShare>,
        hostSecretKeys: Map<ConfederationRoleId, PrivateKey>,
        selection: ConfederationSignerSelection,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        scriptTree: ScriptTree?,
        signingSessionId: ByteVector32,
    ): Either<Throwable, ByteVector64> {
        val tapTweak = scriptTree?.let { Crypto.TaprootTweak.ScriptPathTweak(it.hash()) } ?: Crypto.TaprootTweak.KeyPathTweak
        val txHash = Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, inputs, SigHash.SIGHASH_DEFAULT)
        return signLocal(keyState, shares, hostSecretKeys, selection, listOf(ConfederationTweak.taproot(keyState.publicKey, tapTweak)), signingSessionId, txHash)
    }

    /** Wrap [role]'s 32-byte secret share, after checking it against the role's public share in [keyState]. */
    @JvmStatic
    public fun wrapShare(role: ConfederationRoleId, secretShare: PrivateKey, keyState: ConfederationKeyState): Either<Throwable, ConfederationShare> = try {
        Either.Right(ConfederationShare(role, Secp256k1.confederationShareWrap(role.groupId, role.adminId, secretShare.value.toByteArray(), keyState.native, keyState.roster.native)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /**
     * Issue a recovery package for a newly created [share]. [transitionHash] must be the hash of the validated
     * certificate that created it, and [recoveryNonce] fresh.
     */
    @JvmStatic
    public fun issueRecovery(
        share: ConfederationShare,
        hostSecretKey: PrivateKey,
        keyState: ConfederationKeyState,
        operation: ConfederationOperation,
        transitionHash: ByteVector32,
        recoveryNonce: ByteVector32,
    ): Either<Throwable, ConfederationRecoveryPackage> = try {
        val native = Secp256k1.confederationRecoveryIssue(
            share.native, hostSecretKey.value.toByteArray(), keyState.native, keyState.roster.native,
            operation.code, transitionHash.toByteArray(), recoveryNonce.toByteArray(),
        )
        Either.Right(ConfederationRecoveryPackage.fromNative(native))
    } catch (t: Throwable) {
        Either.Left(t)
    }
}
