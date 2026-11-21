package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.ConfederationStep
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * A fault a confederation step attributes to another party: [kind], and the role it implicates, or null when no
 * single role is implicated. A fault is the protocol's answer, not an error: the caller records it and decides
 * whether to retry without that role, to investigate, or to abandon the attempt.
 */
public data class ConfederationFault(val kind: Kind, val role: ConfederationRoleId?) {
    public enum class Kind(public val code: Int) {
        /** The roster and keys produce an invalid configuration, such as an infinite aggregate. Nobody's fault. */
        INVALID_CONFIGURATION(fr.acinq.secp256k1.ConfederationFault.INVALID_CONFIGURATION),

        /** The coordinator sent something no honest coordinator sends. */
        COORDINATOR(fr.acinq.secp256k1.ConfederationFault.COORDINATOR),

        /** [role] sent something no honest role sends. */
        ROLE(fr.acinq.secp256k1.ConfederationFault.ROLE),

        /** Either [role] or the coordinator, who relayed it: an investigation decides which. */
        ROLE_OR_COORDINATOR(fr.acinq.secp256k1.ConfederationFault.ROLE_OR_COORDINATOR),

        /** [role]'s message does not verify, and this party cannot tell who altered it. */
        UNKNOWN(fr.acinq.secp256k1.ConfederationFault.UNKNOWN);

        internal companion object {
            fun of(code: Int): Kind = requireNotNull(entries.firstOrNull { it.code == code }) { "unexpected confederation fault code $code" }
        }
    }

    internal companion object {
        /** Null for no fault; the role index is the flattened RPD index, named here by role. */
        fun of(fault: fr.acinq.secp256k1.ConfederationFault, roster: ConfederationRoster): ConfederationFault? =
            if (fault.code == fr.acinq.secp256k1.ConfederationFault.NONE) null
            else ConfederationFault(Kind.of(fault.code), fault.roleIndex?.let { roster.roleIds[it.toInt()] })
    }
}

/** A role's signed dealer record (step 1). Public: every role and the coordinator see it. */
public data class ConfederationDealerRecord(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** A role's vector of encrypted evaluations, one per role (step 1). Sent to the coordinator, who relays it. */
public data class ConfederationCiphertexts(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** The coordinator's broadcast (step 2): every record and every role's summed ciphertext. */
public data class ConfederationBroadcast(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** Every role's authorization or acknowledgment of the genesis transition, in roster order (steps 4 and 6). */
public data class ConfederationEvidenceList(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** One dealer's answer to an investigation (protocol section 7.5), produced by the coordinator from its ciphertexts. */
public data class ConfederationInvestigationResponse(val data: ByteVector) {
    public fun toByteArray(): ByteArray = data.toByteArray()
}

/** What step 1 gives a role: its record and its ciphertexts. Store both before sending them, then erase the dealer seed. */
public data class ConfederationDkgDealing(val record: ConfederationDealerRecord, val ciphertexts: ConfederationCiphertexts)

/** Step 2: the broadcast, or the role whose record or ciphertexts failed. */
public data class ConfederationCoordinatorStep1Result(val fault: ConfederationFault?, val broadcast: ConfederationBroadcast?)

/** Step 3: the key state the role derived itself, the genesis transition's hash and the role's authorization of it. */
public data class ConfederationParticipantStep2Result(val fault: ConfederationFault?, val keyState: ConfederationKeyState?, val transitionHash: ByteVector32?, val authorization: ByteVector64?)

/** Step 5: the role's acknowledgment, or the role whose authorization did not verify. */
public data class ConfederationAcknowledgeResult(val fault: ConfederationFault?, val acknowledgment: ByteVector64?)

/** Step 6: the certified genesis transition, or the role whose evidence did not verify. */
public data class ConfederationCoordinatorFinalizeResult(val fault: ConfederationFault?, val genesis: ConfederationTransition?)

/** Step 7: the role's share and its recovery package. The share is secret. */
public class ConfederationParticipantFinalizeResult(public val share: ConfederationShare, public val recovery: ConfederationRecoveryPackage) {
    override fun toString(): String = "ConfederationParticipantFinalizeResult(role=${share.role}, <secret>)"
}

/** Which evidence a list carries: the authorizations of step 3, or the acknowledgments of step 5. */
public enum class ConfederationEvidencePurpose(internal val code: Int) {
    AUTHORIZE(Secp256k1.CONFEDERATION_EVIDENCE_AUTHORIZE),
    ACKNOWLEDGE(Secp256k1.CONFEDERATION_EVIDENCE_ACKNOWLEDGE),
}

/**
 * The confederation's initial DKG, one role at a time: every role on its own device, the coordinator relaying
 * bytes. The steps, and what each role must durably store between them, are those of protocol section 7:
 *
 *  1. every role:  [participantStep1]       -> dealing (store it, send it, then erase the dealer seed)
 *  2. coordinator: [coordinatorStep1]       -> broadcast
 *  3. every role:  [participantStep2]       -> its own key state, the genesis hash and its authorization
 *  4. coordinator: [evidenceList]           -> authorization list
 *  5. every role:  store the roster, key state, broadcast, own record and recovery nonce, then
 *                  [participantAcknowledge] -> acknowledgment
 *  6. coordinator: [evidenceList], [deriveKeyState], [coordinatorFinalize] -> certified genesis
 *  7. every role:  [participantFinalize]    -> share and recovery package
 *
 * Every step is a deterministic function of its arguments, so a role that restarts recomputes a step from what it
 * stored. Randomness is explicit and must be fresh. A step that judges another party's message reports a
 * [ConfederationFault] in its result. As in [Confederation], an argument this caller got wrong (a role not in the
 * roster, a host key that is not the role's, a missing role, a message of the wrong size) raises
 * [IllegalArgumentException]; [Either.Left] carries what the native library refused.
 *
 * WARNING: experimental research code, unaudited, not for production or for protecting value; see [Confederation].
 */
public object ConfederationDkg {
    /** The lengths of the DKG messages for [roster]. */
    @JvmStatic
    public fun messageSizes(roster: ConfederationRoster): fr.acinq.secp256k1.ConfederationDkgMessageSizes = Secp256k1.confederationDkgMessageSizes(roster.native)

    private inline fun <T> local(block: () -> T): Either<Throwable, T> = try {
        Either.Right(block())
    } catch (t: Throwable) {
        Either.Left(t)
    }

    /** The host key as bytes, after checking it is [role]'s. The caller wipes it. */
    private fun hostKey(roster: ConfederationRoster, role: ConfederationRoleId, hostSecretKey: PrivateKey): ByteArray {
        val entry = requireNotNull(roster.role(role)) { "$role is not in the roster" }
        require(hostSecretKey.publicKey() == entry.hostPublicKey) { "the host secret key does not match $role's host public key" }
        return hostSecretKey.value.toByteArray()
    }

    private fun <T> keyedByRole(roster: ConfederationRoster, values: Map<ConfederationRoleId, T>, what: String): List<T> {
        require(values.keys == roster.roleIds.toSet()) { "expected $what for exactly the roles ${roster.roleIds}, got ${values.keys.sorted()}" }
        return roster.roleIds.map { values.getValue(it) }
    }

    private fun requireSize(what: String, actual: Int, expected: Int) = require(actual == expected) { "$what must be $expected bytes for this roster, got $actual" }

    /** Step 1, every role: its dealer record and ciphertexts. [dealerSeed] is a fresh single-use secret. */
    @JvmStatic
    public fun participantStep1(
        roster: ConfederationRoster,
        role: ConfederationRoleId,
        hostSecretKey: PrivateKey,
        dealerSeed: ByteVector32,
        sessionSeed: ByteVector32,
    ): Either<Throwable, ConfederationDkgDealing> {
        val host = hostKey(roster, role, hostSecretKey)
        val seed = dealerSeed.toByteArray()
        return try {
            local {
                val dealing = Secp256k1.confederationDkgParticipantStep1(roster.native, role.groupId, role.adminId, host, seed, sessionSeed.toByteArray())
                ConfederationDkgDealing(ConfederationDealerRecord(ByteVector(dealing.record)), ConfederationCiphertexts(ByteVector(dealing.ciphertexts)))
            }
        } finally {
            host.fill(0)
            seed.fill(0)
        }
    }

    /** Step 2, coordinator: check every role's dealing and write the broadcast. */
    @JvmStatic
    public fun coordinatorStep1(
        roster: ConfederationRoster,
        sessionSeed: ByteVector32,
        dealings: Map<ConfederationRoleId, ConfederationDkgDealing>,
    ): Either<Throwable, ConfederationCoordinatorStep1Result> {
        val ordered = keyedByRole(roster, dealings, "a dealing")
        val sizes = messageSizes(roster)
        ordered.forEach {
            requireSize("a dealer record", it.record.data.size(), sizes.record)
            requireSize("a ciphertext vector", it.ciphertexts.data.size(), sizes.ciphertexts)
        }
        return local {
            val records = ordered.fold(ByteArray(0)) { acc, it -> acc + it.record.toByteArray() }
            val ciphertexts = ordered.fold(ByteArray(0)) { acc, it -> acc + it.ciphertexts.toByteArray() }
            when (val step = Secp256k1.confederationDkgCoordinatorStep1(roster.native, sessionSeed.toByteArray(), records, ciphertexts)) {
                is ConfederationStep.Done -> ConfederationCoordinatorStep1Result(null, ConfederationBroadcast(ByteVector(step.value)))
                is ConfederationStep.Faulted -> ConfederationCoordinatorStep1Result(ConfederationFault.of(step.fault, roster), null)
            }
        }
    }

    /** The key state a broadcast determines. Every role derives it inside [participantStep2]; the coordinator calls this before finalizing. */
    @JvmStatic
    public fun deriveKeyState(roster: ConfederationRoster, broadcast: ConfederationBroadcast): Either<Throwable, ConfederationKeyState> = local {
        ConfederationKeyState.fromNative(Secp256k1.confederationDkgDeriveKsd(roster.native, broadcast.toByteArray()), roster)
    }

    /**
     * Step 3, every role: every check of protocol section 7.4 on the broadcast, the key state derived by this role
     * (never accepted from the coordinator), and its authorization of the genesis transition. [ownRecord] is the
     * record this role stored at step 1, and [sessionSeed] the one it accepted at the start.
     */
    @JvmStatic
    public fun participantStep2(
        roster: ConfederationRoster,
        role: ConfederationRoleId,
        hostSecretKey: PrivateKey,
        sessionSeed: ByteVector32,
        ownRecord: ConfederationDealerRecord,
        broadcast: ConfederationBroadcast,
    ): Either<Throwable, ConfederationParticipantStep2Result> {
        val host = hostKey(roster, role, hostSecretKey)
        return try {
            local {
                when (val step = Secp256k1.confederationDkgParticipantStep2(roster.native, role.groupId, role.adminId, host, sessionSeed.toByteArray(), ownRecord.toByteArray(), broadcast.toByteArray())) {
                    is ConfederationStep.Done -> ConfederationParticipantStep2Result(
                        null,
                        ConfederationKeyState.fromNative(step.value.ksd, roster),
                        ByteVector32(step.value.transitionHash),
                        ByteVector64(step.value.authorization),
                    )
                    is ConfederationStep.Faulted -> ConfederationParticipantStep2Result(ConfederationFault.of(step.fault, roster), null, null, null)
                }
            }
        } finally {
            host.fill(0)
        }
    }

    /** Steps 4 and 6, coordinator: every role's signature, authorization or acknowledgment, as one list. */
    @JvmStatic
    public fun evidenceList(roster: ConfederationRoster, signatures: Map<ConfederationRoleId, ByteVector64>): Either<Throwable, ConfederationEvidenceList> {
        val ordered = keyedByRole(roster, signatures, "a signature")
        return local {
            ConfederationEvidenceList(ByteVector(Secp256k1.confederationDkgEvidenceListWrite(roster.native, ordered.map { it.toByteArray() }.toTypedArray())))
        }
    }

    /** Check every role's evidence over [transitionHash]: null when it all verifies, else who is at fault. */
    @JvmStatic
    public fun verifyEvidence(
        roster: ConfederationRoster,
        transitionHash: ByteVector32,
        purpose: ConfederationEvidencePurpose,
        evidence: ConfederationEvidenceList,
    ): Either<Throwable, ConfederationFault?> = local {
        Secp256k1.confederationDkgVerifyEvidence(roster.native, transitionHash.toByteArray(), purpose.code, evidence.toByteArray())?.let { ConfederationFault.of(it, roster) }
    }

    /**
     * Step 5, every role: verify every authorization, then acknowledge. Call it only after durably storing the
     * roster, the key state, the broadcast, the role's own record and its recovery nonce: the acknowledgment tells
     * the others this role can never lose its share. [transitionHash] is this role's own, from [participantStep2].
     */
    @JvmStatic
    public fun participantAcknowledge(
        roster: ConfederationRoster,
        role: ConfederationRoleId,
        hostSecretKey: PrivateKey,
        transitionHash: ByteVector32,
        authorizations: ConfederationEvidenceList,
    ): Either<Throwable, ConfederationAcknowledgeResult> {
        val host = hostKey(roster, role, hostSecretKey)
        return try {
            local {
                when (val step = Secp256k1.confederationDkgParticipantAcknowledge(roster.native, role.groupId, role.adminId, host, transitionHash.toByteArray(), authorizations.toByteArray())) {
                    is ConfederationStep.Done -> ConfederationAcknowledgeResult(null, ByteVector64(step.value))
                    is ConfederationStep.Faulted -> ConfederationAcknowledgeResult(ConfederationFault.of(step.fault, roster), null)
                }
            }
        } finally {
            host.fill(0)
        }
    }

    /** Step 6, coordinator: the certified genesis, over the coordinator's own [keyState] from [deriveKeyState]. */
    @JvmStatic
    public fun coordinatorFinalize(
        keyState: ConfederationKeyState,
        authorizations: ConfederationEvidenceList,
        acknowledgments: ConfederationEvidenceList,
    ): Either<Throwable, ConfederationCoordinatorFinalizeResult> = local {
        val roster = keyState.roster
        when (val step = Secp256k1.confederationDkgCoordinatorFinalize(roster.native, keyState.native, authorizations.toByteArray(), acknowledgments.toByteArray())) {
            is ConfederationStep.Done -> ConfederationCoordinatorFinalizeResult(null, ConfederationTransition.fromNative(step.value, null, keyState))
            is ConfederationStep.Faulted -> ConfederationCoordinatorFinalizeResult(ConfederationFault.of(step.fault, roster), null)
        }
    }

    /**
     * Step 7, every role: check the certified [genesis], recompute the share from [ownRecord] and the broadcast, and
     * issue its recovery package with a fresh [recoveryNonce]. [keyState] is the role's own, from [participantStep2].
     */
    @JvmStatic
    public fun participantFinalize(
        genesis: ConfederationTransition,
        keyState: ConfederationKeyState,
        role: ConfederationRoleId,
        hostSecretKey: PrivateKey,
        ownRecord: ConfederationDealerRecord,
        broadcast: ConfederationBroadcast,
        recoveryNonce: ByteVector32,
    ): Either<Throwable, ConfederationParticipantFinalizeResult> {
        val roster = keyState.roster
        val host = hostKey(roster, role, hostSecretKey)
        val nonce = recoveryNonce.toByteArray()
        return try {
            local {
                val result = Secp256k1.confederationDkgParticipantFinalize(
                    genesis.native, roster.native, keyState.native, role.groupId, role.adminId, host, ownRecord.toByteArray(), broadcast.toByteArray(), nonce,
                )
                ConfederationParticipantFinalizeResult(ConfederationShare(role, result.share), ConfederationRecoveryPackage.fromNative(result.recovery))
            }
        } finally {
            host.fill(0)
            nonce.fill(0)
        }
    }

    /** Protocol section 7.5, coordinator: [dealer]'s investigation response, from the ciphertexts it received from it. */
    @JvmStatic
    public fun investigationResponse(
        roster: ConfederationRoster,
        sessionSeed: ByteVector32,
        dealer: ConfederationRoleId,
        ciphertexts: ConfederationCiphertexts,
    ): Either<Throwable, ConfederationInvestigationResponse> {
        requireNotNull(roster.role(dealer)) { "$dealer is not in the roster" }
        requireSize("a ciphertext vector", ciphertexts.data.size(), messageSizes(roster).ciphertexts)
        return local {
            ConfederationInvestigationResponse(ByteVector(Secp256k1.confederationDkgInvestigationResponse(roster.native, sessionSeed.toByteArray(), dealer.groupId, dealer.adminId, ciphertexts.toByteArray())))
        }
    }

    /**
     * Protocol section 7.5, a role whose share did not decrypt at step 3: judge every dealer's response. Null when
     * nobody is at fault; otherwise the coordinator, or the dealer that sent a bad share.
     */
    @JvmStatic
    public fun investigate(
        roster: ConfederationRoster,
        role: ConfederationRoleId,
        hostSecretKey: PrivateKey,
        broadcast: ConfederationBroadcast,
        responses: Map<ConfederationRoleId, ConfederationInvestigationResponse>,
    ): Either<Throwable, ConfederationFault?> {
        val ordered = keyedByRole(roster, responses, "an investigation response")
        val size = messageSizes(roster).investigationResponse
        ordered.forEach { requireSize("an investigation response", it.data.size(), size) }
        val host = hostKey(roster, role, hostSecretKey)
        return try {
            local {
                val all = ordered.fold(ByteArray(0)) { acc, it -> acc + it.toByteArray() }
                ConfederationFault.of(Secp256k1.confederationDkgInvestigate(roster.native, role.groupId, role.adminId, host, broadcast.toByteArray(), all), roster)
            }
        } finally {
            host.fill(0)
        }
    }
}
