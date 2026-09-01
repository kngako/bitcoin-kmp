package fr.acinq.bitcoin.crypto.dkg.chill

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.ChilldkgFault
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * ChillDKG participant state after the first step of a DKG session (see [ChillDKG.participantStep1]).
 * This should be treated as a private opaque blob: it must be kept until [ChillDKG.participantStep2] and must not
 * be reused afterwards.
 */
public data class ParticipantState1(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE) { "chilldkg participant state1 must be ${Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * ChillDKG participant state after the second step of a DKG session (see [ChillDKG.participantStep2]).
 * This should be treated as a private opaque blob: it must be kept until [ChillDKG.participantFinalize] and must
 * not be reused afterwards.
 */
public data class ParticipantState2(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE) { "chilldkg participant state2 must be ${Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * ChillDKG coordinator state (see [ChillDKG.coordinatorStep1]).
 * This should be treated as a private opaque blob: it must be kept until [ChillDKG.coordinatorFinalize] and must
 * not be reused afterwards.
 */
public data class CoordinatorState(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE) { "chilldkg coordinator state must be ${Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * ChillDKG investigation data (see [ChillDKG.participantStep2]), allowing a participant to investigate who is to
 * blame for a failed DKG session (see [ChillDKG.participantInvestigate]).
 * This should be treated as a private opaque blob: it must not be shared.
 */
public data class InvestigationData(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE) { "chilldkg investigation data must be ${Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/** Result of [ChillDKG.participantStep1]. */
public data class ParticipantStep1Result(
    /** Session state to keep until [ChillDKG.participantStep2]. */
    val state: ParticipantState1,
    /** Message to send to the coordinator (pmsg1). */
    val message: ByteVector
)

/** Result of [ChillDKG.coordinatorStep1]. On fault, [state] and [message] are zeroed. */
public data class CoordinatorStep1Result(
    /** Fault report: protocol faults are normal outcomes of a DKG session and are reported here, not as exceptions. */
    val fault: ChilldkgFault,
    /** Session state to keep until [ChillDKG.coordinatorFinalize]. */
    val state: CoordinatorState,
    /** Message to broadcast to all participants (cmsg1). */
    val message: ByteVector
)

/** Result of [ChillDKG.participantStep2]. On fault, [state] and [certEqSignature] are zeroed. */
public data class ParticipantStep2Result(
    /** Fault report: protocol faults are normal outcomes of a DKG session and are reported here, not as exceptions. */
    val fault: ChilldkgFault,
    /** Session state to keep until [ChillDKG.participantFinalize]. */
    val state: ParticipantState2,
    /** CertEq signature to send to the coordinator (pmsg2). */
    val certEqSignature: ByteVector64,
    /** Investigation data for [ChillDKG.participantInvestigate]: only set when the fault code is
     * [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR]. */
    val investigationData: InvestigationData?
)

/** Result of [ChillDKG.coordinatorFinalize]. On fault, [certificate] is zeroed and the DKG output is null. */
public data class CoordinatorFinalizeResult(
    /** Fault report: protocol faults are normal outcomes of a DKG session and are reported here, not as exceptions. */
    val fault: ChilldkgFault,
    /** Certificate to broadcast to all participants (cmsg2). */
    val certificate: ByteVector,
    /** Threshold public key of the DKG session. */
    val thresholdPublicKey: PublicKey?,
    /** Public shares of all participants (entry i belongs to participant id i). */
    val publicShares: List<PublicKey>,
    /** Recovery data of the session. */
    val recovery: ByteVector?
)

/** Result of [ChillDKG.participantFinalize]. If [fault] is ok, this participant deems the DKG session successful. */
public data class ParticipantFinalizeResult(
    /** Fault report: protocol faults are normal outcomes of a DKG session and are reported here, not as exceptions. */
    val fault: ChilldkgFault,
    /** The participant's secret share (sensitive data that must be stored securely). */
    val secretShare: PrivateKey?,
    /** Threshold public key of the DKG session. */
    val thresholdPublicKey: PublicKey?,
    /** Public shares of all participants (entry i belongs to participant id i). */
    val publicShares: List<PublicKey>,
    /** Recovery data of the session: all participants and the coordinator obtain the same recovery data. */
    val recovery: ByteVector?
)

/** Result of [ChillDKG.participantRecover] and [ChillDKG.coordinatorRecover]. */
public data class RecoverResult(
    /** Fault report. */
    val fault: ChilldkgFault,
    /** The participant's secret share: null for the coordinator, who has no secret share. */
    val secretShare: PrivateKey?,
    /** Threshold public key of the recovered session. */
    val thresholdPublicKey: PublicKey?,
    /** Public shares of all participants (entry i belongs to participant id i). */
    val publicShares: List<PublicKey>,
    /** Host public keys of all participants (entry i belongs to participant id i). */
    val hostPublicKeys: List<PublicKey>,
    /** Total number of participants of the recovered session. */
    val nParticipants: Int,
    /** Threshold of the recovered session. */
    val threshold: Int
)

/**
 * This object contains the ChillDKG distributed key generation protocol (from the bip-frost-dkg specification).
 * ChillDKG lets a group of n participants generate FROST threshold key material (see
 * [fr.acinq.bitcoin.crypto.frost.Frost]) without a trusted dealer, with the help of a coordinator (which may be one
 * of the participants and doesn't learn any secret).
 *
 * Protocol overview:
 * 1. every participant runs [participantStep1] and sends its message to the coordinator,
 * 2. the coordinator runs [coordinatorStep1] and broadcasts its message to all participants,
 * 3. every participant runs [participantStep2] and sends its CertEq signature to the coordinator,
 * 4. the coordinator runs [coordinatorFinalize] and broadcasts the certificate to all participants,
 * 5. every participant runs [participantFinalize] and obtains its secret share and the session's public data.
 *
 * Protocol faults (a faulty participant or coordinator) are normal outcomes of a DKG session: they are reported in
 * the [ChilldkgFault] field of each result instead of exceptions. Exceptions are only raised for invalid local
 * inputs (e.g. invalid host secret key or malformed state blobs).
 *
 * WARNING: the underlying secp256k1 ChillDKG module is experimental and must not be used in production.
 */
public object ChillDKG {
    /**
     * Compute the host public key of a participant. The host public key is the long-term cryptographic identity of
     * the participant in DKG sessions.
     *
     * @param hostSecretKey host secret key.
     * @return the host public key.
     */
    @JvmStatic
    public fun hostPublicKey(hostSecretKey: PrivateKey): PublicKey {
        return PublicKey(Secp256k1.chilldkgHostpubkeyGen(hostSecretKey.value.toByteArray()))
    }

    /**
     * Compute a hash of the session parameters, for out-of-band comparison between participants. If all
     * participants obtain the same hash, they all agree on the host public keys and the threshold.
     *
     * @param hostPublicKeys host public keys of all participants (in the order agreed upon by all participants).
     * @param threshold threshold t: the number of signers required to produce a signature.
     * @return 32-byte hash of the session parameters.
     */
    @JvmStatic
    public fun sessionParamsHash(hostPublicKeys: List<PublicKey>, threshold: Int): ByteVector32 {
        return Secp256k1.chilldkgParamsHash(hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold).byteVector32()
    }

    /**
     * Perform a participant's first step of a DKG session.
     *
     * @param hostSecretKey host secret key.
     * @param hostPublicKeys host public keys of all participants; all participants must agree on the order.
     * @param threshold threshold t.
     * @param random 32 bytes of fresh randomness.
     * @return the participant's session state and the message to send to the coordinator.
     */
    @JvmStatic
    public fun participantStep1(hostSecretKey: PrivateKey, hostPublicKeys: List<PublicKey>, threshold: Int, random: ByteVector32): ParticipantStep1Result {
        val (state, pmsg1) = Secp256k1.chilldkgParticipantStep1(hostSecretKey.value.toByteArray(), hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold, random.toByteArray())
        return ParticipantStep1Result(ParticipantState1(state), pmsg1.byteVector())
    }

    /**
     * Perform the coordinator's first step of a DKG session: aggregate the participants' first messages into the
     * message to broadcast to all participants.
     *
     * @param participantMessages the participants' first messages (see [participantStep1]), in the same order as
     * [hostPublicKeys].
     * @param hostPublicKeys host public keys of all participants; must be identical (in content and order) to the
     * lists used by the participants.
     * @param threshold threshold t.
     * @return the fault report, the coordinator's session state and the message to broadcast to all participants.
     */
    @JvmStatic
    public fun coordinatorStep1(participantMessages: List<ByteVector>, hostPublicKeys: List<PublicKey>, threshold: Int): CoordinatorStep1Result {
        val result = Secp256k1.chilldkgCoordinatorStep1(participantMessages.map { it.toByteArray() }.toTypedArray(), hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold)
        return CoordinatorStep1Result(result.fault, CoordinatorState(result.state), result.cmsg1.byteVector())
    }

    /**
     * Perform a participant's second step of a DKG session: verify the coordinator's first message, compute the
     * DKG output, and produce the CertEq signature over the session transcript.
     *
     * Warning: after sending the produced signature to the coordinator, the caller must not erase its host secret
     * key, even if the coordinator's reply needed for [participantFinalize] is not received (some other participant
     * may deem the session successful and use the resulting threshold public key).
     *
     * @param hostSecretKey host secret key (must be the same as in [participantStep1]).
     * @param state session state output by [participantStep1] (must not be reused).
     * @param coordinatorMessage the coordinator's first message (see [coordinatorStep1]).
     * @param auxRand 32 bytes of auxiliary randomness for the CertEq signature (see BIP 340).
     * @return the fault report, the participant's session state, the CertEq signature to send to the coordinator,
     * and the investigation data (only set when the fault code is [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR]).
     */
    @JvmStatic
    public fun participantStep2(hostSecretKey: PrivateKey, state: ParticipantState1, coordinatorMessage: ByteVector, auxRand: ByteVector32): ParticipantStep2Result {
        val result = Secp256k1.chilldkgParticipantStep2(hostSecretKey.value.toByteArray(), state.toByteArray(), coordinatorMessage.toByteArray(), auxRand.toByteArray())
        return ParticipantStep2Result(result.fault, ParticipantState2(result.state2), result.sig64.byteVector64(), result.investigationData?.let { InvestigationData(it) })
    }

    /**
     * Perform the coordinator's final step of a DKG session: collect the CertEq signatures into the certificate and
     * verify all of them.
     *
     * @param state coordinator's session state output by [coordinatorStep1] (must not be reused).
     * @param certEqSignatures the participants' CertEq signatures (see [participantStep2]), in the same order as
     * the host public keys.
     * @param threshold threshold t.
     * @return the fault report, the certificate to broadcast to all participants, and the DKG output.
     */
    @JvmStatic
    public fun coordinatorFinalize(state: CoordinatorState, certEqSignatures: List<ByteVector64>, threshold: Int): CoordinatorFinalizeResult {
        val result = Secp256k1.chilldkgCoordinatorFinalize(state.toByteArray(), certEqSignatures.map { it.toByteArray() }.toTypedArray(), threshold)
        return CoordinatorFinalizeResult(
            result.fault,
            result.cmsg2.byteVector(),
            result.thresholdPubkey.toPublicKeyOrNull(result.fault.isOk),
            result.pubshares.toPublicKeys(result.fault.isOk),
            result.recovery.byteVector().takeIf { result.fault.isOk }
        )
    }

    /**
     * Perform a participant's final step of a DKG session: verify the certificate and compute the DKG output.
     *
     * @param state session state output by [participantStep2] (must not be reused).
     * @param certificate the certificate (see [coordinatorFinalize]).
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the fault report, the participant's secret share, and the DKG output.
     */
    @JvmStatic
    public fun participantFinalize(state: ParticipantState2, certificate: ByteVector, nParticipants: Int, threshold: Int): ParticipantFinalizeResult {
        val result = Secp256k1.chilldkgParticipantFinalize(state.toByteArray(), certificate.toByteArray(), nParticipants, threshold)
        return ParticipantFinalizeResult(
            result.fault,
            result.secshare.toPrivateKeyOrNull(result.fault.isOk),
            result.thresholdPubkey.toPublicKeyOrNull(result.fault.isOk),
            result.pubshares.toPublicKeys(result.fault.isOk),
            result.recovery.byteVector().takeIf { result.fault.isOk }
        )
    }

    /**
     * Recover a participant's DKG output from recovery data, e.g. after a failure of [participantFinalize] (using
     * recovery data obtained from another participant or the coordinator) or after data loss. The recovery data is
     * self-delimiting: the number of participants and the threshold are derived from it.
     *
     * @param hostSecretKey host secret key.
     * @param recovery the recovery data of the session.
     * @return the fault report, the participant's secret share, and the public data of the recovered session.
     */
    @JvmStatic
    public fun participantRecover(hostSecretKey: PrivateKey, recovery: ByteVector): RecoverResult {
        val result = Secp256k1.chilldkgParticipantRecover(hostSecretKey.value.toByteArray(), recovery.toByteArray())
        return recoverResult(result)
    }

    /**
     * Recover the DKG output of the coordinator from recovery data. Like [participantRecover], but for the
     * coordinator, who has no secret share.
     *
     * @param recovery the recovery data of the session.
     */
    @JvmStatic
    public fun coordinatorRecover(recovery: ByteVector): RecoverResult {
        val result = Secp256k1.chilldkgCoordinatorRecover(recovery.toByteArray())
        return recoverResult(result)
    }

    /**
     * Sign recovery data to create a recovery acknowledgment. Acks can be collected in an optional acknowledgment
     * round to confirm that all participants have received the recovery data.
     *
     * @param hostSecretKey host secret key.
     * @param hostPublicKeys host public keys of all participants.
     * @param threshold threshold t.
     * @param recovery the recovery data of the session.
     * @param auxRand 32 bytes of auxiliary randomness (see BIP 340).
     * @return the 64-byte acknowledgment signature.
     */
    @JvmStatic
    public fun recoveryAckSign(hostSecretKey: PrivateKey, hostPublicKeys: List<PublicKey>, threshold: Int, recovery: ByteVector, auxRand: ByteVector32): ByteVector64 {
        return Secp256k1.chilldkgRecoveryAckSign(hostSecretKey.value.toByteArray(), hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold, recovery.toByteArray(), auxRand.toByteArray()).byteVector64()
    }

    /**
     * Verify the recovery acknowledgment signatures of all participants. Note that a failure does NOT mean the DKG
     * failed (reaching this point implies the DKG itself was successful); it only means it cannot be confirmed that
     * all participants have a copy of the recovery data.
     *
     * @param hostPublicKeys host public keys of all participants.
     * @param threshold threshold t.
     * @param recovery the recovery data of the session.
     * @param ackSignatures the acknowledgment signatures, in the same order as [hostPublicKeys].
     * @return the fault report (ok if all signatures are valid).
     */
    @JvmStatic
    public fun recoveryAcksVerify(hostPublicKeys: List<PublicKey>, threshold: Int, recovery: ByteVector, ackSignatures: List<ByteVector64>): ChilldkgFault {
        return Secp256k1.chilldkgRecoveryAcksVerify(hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold, recovery.toByteArray(), ackSignatures.map { it.toByteArray() }.toTypedArray())
    }

    /**
     * Generate the investigation message for a single participant, which allows that participant to investigate who
     * is to blame for a failed DKG session (see [participantInvestigate]). The message contains no confidential
     * information and can be safely broadcast.
     *
     * @param participantMessages the participants' first messages, in the same order as [hostPublicKeys].
     * @param hostPublicKeys host public keys of all participants.
     * @param threshold threshold t.
     * @param participantId the participant the investigation message is for.
     * @return the fault report and the investigation message for the given participant.
     */
    @JvmStatic
    public fun coordinatorInvestigate(participantMessages: List<ByteVector>, hostPublicKeys: List<PublicKey>, threshold: Int, participantId: UInt): Pair<ChilldkgFault, ByteVector> {
        val (fault, cinv) = Secp256k1.chilldkgCoordinatorInvestigate(participantMessages.map { it.toByteArray() }.toTypedArray(), hostPublicKeys.map { it.value.toByteArray() }.toTypedArray(), threshold, participantId)
        return Pair(fault, cinv.byteVector())
    }

    /**
     * Investigate who is to blame for a failed DKG session. Can be called when [participantStep2] returned
     * [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR].
     *
     * @param investigationData the investigation data output by [participantStep2] (secret, must not be shared).
     * @param coordinatorInvestigationMessage the coordinator's investigation message for this participant (see
     * [coordinatorInvestigate]).
     * @return the fault report identifying the suspected faulty party.
     */
    @JvmStatic
    public fun participantInvestigate(investigationData: InvestigationData, coordinatorInvestigationMessage: ByteVector): ChilldkgFault {
        return Secp256k1.chilldkgParticipantInvestigate(investigationData.toByteArray(), coordinatorInvestigationMessage.toByteArray())
    }

    private fun recoverResult(result: fr.acinq.secp256k1.ChilldkgRecoverResult): RecoverResult {
        return RecoverResult(
            result.fault,
            result.secshare.toPrivateKeyOrNull(result.fault.isOk),
            result.thresholdPubkey.toPublicKeyOrNull(result.fault.isOk),
            result.pubshares.toPublicKeys(result.fault.isOk),
            result.hostpubkeys.toPublicKeys(result.fault.isOk),
            result.nParticipants,
            result.threshold
        )
    }

    // On fault, the fork's outputs are zeroed blobs that don't hold valid keys: expose them as null instead.
    private fun ByteArray?.toPrivateKeyOrNull(valid: Boolean): PrivateKey? = if (valid && this != null) PrivateKey(this) else null
    private fun ByteArray.toPublicKeyOrNull(valid: Boolean): PublicKey? = if (valid) PublicKey(this) else null
    private fun Array<ByteArray>.toPublicKeys(valid: Boolean): List<PublicKey> = if (valid) this.map { PublicKey(it) } else listOf()
}
