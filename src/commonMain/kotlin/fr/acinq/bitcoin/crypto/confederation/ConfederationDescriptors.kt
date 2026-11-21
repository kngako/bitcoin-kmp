package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/** A role in a confederation roster: admin [adminId] of outer group [groupId]. Ordered as the roster flattens roles. */
public data class ConfederationRoleId(val groupId: UInt, val adminId: UInt) : Comparable<ConfederationRoleId> {
    override fun compareTo(other: ConfederationRoleId): Int = compareValuesBy(this, other, { it.groupId }, { it.adminId })
    override fun toString(): String = "($groupId, $adminId)"
}

/**
 * One role record of a [ConfederationRoster].
 *
 * [entityId] is externally attested metadata, not a proof of personhood or independence: two roles held by the same
 * real-world entity must carry the same [entityId] for [ConfederationRoster.access] to mean anything.
 */
public data class ConfederationRole(val id: ConfederationRoleId, val entityId: ByteVector32, val hostPublicKey: PublicKey)

/** One outer group: [threshold] of its [roles] sign for it, at its current [shareEpoch]. */
public data class ConfederationGroup(val groupId: UInt, val shareEpoch: ULong, val threshold: Int, val roles: List<ConfederationRole>)

/**
 * Exact minimum coalition sizes, in distinct entities: [minSigners] can produce a signature, and the absence of
 * [minBlockers] leaves no authorized coalition. Conditional on the roster's entity attestation.
 */
public data class ConfederationAccess(val minSigners: Int, val minBlockers: Int)

/**
 * The transition operation codes of the confederation protocol (section 2.2). Only [Dkg] is produced by this
 * library at the pinned native revision; the others appear in certificates and recovery packages made elsewhere.
 */
public enum class ConfederationOperation(public val code: Int) {
    Dkg(0),
    AdminEnroll(1),
    AdminRepair(2),
    GroupRefresh(3),
    OuterEnroll(4),
    OuterRebuild(5),
    Reshare(6),
    FullRefresh(7);

    public companion object {
        @JvmStatic
        public fun fromCode(code: Int): ConfederationOperation? = entries.firstOrNull { it.code == code }
    }
}

private fun ByteArray.u32(offset: Int): UInt =
    ((this[offset].toUInt() and 0xffu) shl 24) or
        ((this[offset + 1].toUInt() and 0xffu) shl 16) or
        ((this[offset + 2].toUInt() and 0xffu) shl 8) or
        (this[offset + 3].toUInt() and 0xffu)

private fun ByteArray.u64(offset: Int): ULong = (u32(offset).toULong() shl 32) or u32(offset + 4).toULong()

/**
 * A RosterPolicyDescriptor (RPD): who holds which role, and the outer and inner thresholds.
 *
 * Built with [fromData] from its canonical encoding, which the native module parses and validates in full; the
 * fields below are then read from that already-validated encoding. [data] is what may be stored or sent. The native
 * representation this class also holds is build-specific and never leaves it.
 */
public class ConfederationRoster private constructor(
    /** The canonical encoding (protocol section 3.1). Public. */
    public val data: ByteVector,
    internal val native: ByteArray,
    public val version: Int,
    public val configSeq: ULong,
    public val outerEpoch: ULong,
    /** The hash of the RPD this one succeeds, or null for a genesis roster. */
    public val previousHash: ByteVector32?,
    /** T: how many outer groups must sign. */
    public val outerThreshold: Int,
    public val attestationRef: ByteVector32,
    /** The groups, in ascending identifier order, each with its roles in ascending admin order. */
    public val groups: List<ConfederationGroup>,
) {
    /** TH("Confederation/rpd", [data]). */
    public val hash: ByteVector32 = ByteVector32(Secp256k1.confederationRpdHash(native))

    /** Every role in flattened order: the order of every per-role array the native module takes. */
    public val roles: List<ConfederationRole> = groups.flatMap { it.roles }

    public val roleIds: List<ConfederationRoleId> get() = roles.map { it.id }

    public fun group(groupId: UInt): ConfederationGroup? = groups.firstOrNull { it.groupId == groupId }

    public fun role(id: ConfederationRoleId): ConfederationRole? = roles.firstOrNull { it.id == id }

    /** The role whose host key is [hostPublicKey]: host keys are unique within a roster. */
    public fun roleOf(hostPublicKey: PublicKey): ConfederationRole? = roles.firstOrNull { it.hostPublicKey == hostPublicKey }

    /**
     * Exact entity-overlap analysis. Fails, rather than approximating, for rosters with more than 16 roles.
     */
    public fun access(): Either<Throwable, ConfederationAccess> = try {
        val access = Secp256k1.confederationAccessAnalyze(native)
        Either.Right(ConfederationAccess(access.minSigners, access.minBlockers))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    override fun equals(other: Any?): Boolean = other is ConfederationRoster && other.data == data
    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "ConfederationRoster(configSeq=$configSeq, T=$outerThreshold, groups=${groups.map { "${it.groupId}:${it.threshold}/${it.roles.size}" }}, hash=$hash)"

    public companion object {
        private const val HEADER_SIZE = 96
        private const val GROUP_HEADER_SIZE = 20
        private const val ROLE_SIZE = 69

        /** Parse and validate a canonical RPD. */
        @JvmStatic
        public fun fromData(data: ByteVector): Either<Throwable, ConfederationRoster> = try {
            val bytes = data.toByteArray()
            val native = Secp256k1.confederationRpdParse(bytes)
            Either.Right(read(bytes, native))
        } catch (t: Throwable) {
            Either.Left(t)
        }

        /** Read the fields of an encoding the native parser has already accepted (protocol section 3.1). */
        private fun read(bytes: ByteArray, native: ByteArray): ConfederationRoster {
            val previous = bytes.copyOfRange(24, 56)
            val groupCount = bytes.u32(60).toInt()
            var offset = HEADER_SIZE
            val groups = List(groupCount) {
                val groupId = bytes.u32(offset)
                val shareEpoch = bytes.u64(offset + 4)
                val threshold = bytes.u32(offset + 12).toInt()
                val roleCount = bytes.u32(offset + 16).toInt()
                offset += GROUP_HEADER_SIZE
                val roles = List(roleCount) {
                    val role = ConfederationRole(
                        ConfederationRoleId(groupId, bytes.u32(offset)),
                        ByteVector32(bytes.copyOfRange(offset + 4, offset + 36)),
                        PublicKey(bytes.copyOfRange(offset + 36, offset + 69)),
                    )
                    offset += ROLE_SIZE
                    role
                }
                ConfederationGroup(groupId, shareEpoch, threshold, roles)
            }
            check(offset == bytes.size) { "RPD layout mismatch: read $offset of ${bytes.size} bytes" }
            return ConfederationRoster(
                data = ByteVector(bytes),
                native = native,
                version = bytes.u32(4).toInt(),
                configSeq = bytes.u64(8),
                outerEpoch = bytes.u64(16),
                previousHash = if (previous.all { it == 0.toByte() }) null else ByteVector32(previous),
                outerThreshold = bytes.u32(56).toInt(),
                attestationRef = ByteVector32(bytes.copyOfRange(64, 96)),
                groups = groups,
            )
        }
    }
}

/**
 * A KeyStateDescriptor (KSD): the commitments and public shares of the key a [roster] holds. Contains no secret.
 */
public class ConfederationKeyState private constructor(
    public val roster: ConfederationRoster,
    /** The canonical encoding (protocol section 3.2). Public. */
    public val data: ByteVector,
    internal val native: ByteArray,
) {
    /** TH("Confederation/ksd", [data]). */
    public val hash: ByteVector32 = ByteVector32(Secp256k1.confederationKsdHash(native, roster.native))

    /** The supergroup key X, x-only with even Y: the key untweaked signatures verify under. */
    public val publicKey: XonlyPublicKey = XonlyPublicKey(ByteVector32(Secp256k1.confederationKsdPubkeyGet(native, roster.native)))

    override fun equals(other: Any?): Boolean = other is ConfederationKeyState && other.roster == roster && other.data == data
    override fun hashCode(): Int = 31 * roster.hashCode() + data.hashCode()
    override fun toString(): String = "ConfederationKeyState(publicKey=$publicKey, hash=$hash)"

    public companion object {
        /** Parse and validate a canonical KSD against the roster it belongs to. */
        @JvmStatic
        public fun fromData(data: ByteVector, roster: ConfederationRoster): Either<Throwable, ConfederationKeyState> = try {
            Either.Right(ConfederationKeyState(roster, data, Secp256k1.confederationKsdParse(data.toByteArray(), roster.native)))
        } catch (t: Throwable) {
            Either.Left(t)
        }

        internal fun fromNative(native: ByteArray, roster: ConfederationRoster): ConfederationKeyState =
            ConfederationKeyState(roster, ByteVector(Secp256k1.confederationKsdSerialize(native, roster.native)), native)
    }
}

/**
 * A transition certificate: [previous] (null for genesis) was replaced by [next], with the evidence the protocol
 * requires. A valid certificate proves authorization, not uniqueness: an application must keep its accepted state,
 * accept only a direct successor of it ([isSuccessorOf]), and quarantine [conflictsWith] candidates for its own
 * consensus. Arrival order, signature count and hash order are not resolution rules.
 */
public class ConfederationTransition private constructor(
    public val previous: ConfederationKeyState?,
    public val next: ConfederationKeyState,
    /** The canonical encoding, signatures included (protocol section 4.2). Public. */
    public val data: ByteVector,
    internal val native: ByteArray,
) {
    /** The hash of the unsigned envelope, which recovery packages reference. */
    public val hash: ByteVector32 = ByteVector32(Secp256k1.confederationTransitionHash(native))

    /** The operation this certificate records; non-null because the native parser accepts defined codes only. */
    public val operation: ConfederationOperation = requireNotNull(ConfederationOperation.fromCode(data.toByteArray().u32(8).toInt()))

    public val isGenesis: Boolean get() = previous == null

    /** True for a different authorized successor of the same state and sequence number. Not a validity check. */
    public fun conflictsWith(other: ConfederationTransition): Boolean = Secp256k1.confederationTransitionConflicts(native, other.native)

    /** True if this certificate's predecessor is [current], the state the caller has accepted. */
    public fun isSuccessorOf(current: ConfederationKeyState): Boolean =
        Secp256k1.confederationTransitionCheckSuccessor(native, current.roster.native, current.native)

    override fun equals(other: Any?): Boolean = other is ConfederationTransition && other.data == data
    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "ConfederationTransition(operation=$operation, hash=$hash)"

    public companion object {
        /**
         * Parse a canonical certificate and validate it in full -- sequence rules, required evidence and host
         * signatures -- against the states it claims to connect.
         */
        @JvmStatic
        public fun fromData(data: ByteVector, previous: ConfederationKeyState?, next: ConfederationKeyState): Either<Throwable, ConfederationTransition> = try {
            val native = Secp256k1.confederationTransitionParse(data.toByteArray(), previous?.roster?.native, previous?.native, next.roster.native, next.native)
            Either.Right(ConfederationTransition(previous, next, data, native))
        } catch (t: Throwable) {
            Either.Left(t)
        }

        internal fun fromNative(native: ByteArray, previous: ConfederationKeyState?, next: ConfederationKeyState): ConfederationTransition {
            val data = Secp256k1.confederationTransitionSerialize(native, previous?.roster?.native, previous?.native, next.roster.native, next.native)
            return ConfederationTransition(previous, next, ByteVector(data), native)
        }
    }
}
