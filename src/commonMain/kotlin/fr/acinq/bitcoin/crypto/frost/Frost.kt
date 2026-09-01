@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.jvm.JvmStatic

/**
 * FROST threshold key material (BIP 445): the threshold public key, and the secret and public shares of all
 * participants. Participants are identified by their index in the shares lists (entry i belongs to participant
 * id i).
 *
 * The secret shares are sensitive data: they must be transmitted to their participant over a secure channel and
 * erased from the dealer afterwards. The threshold public key and the public shares are not sensitive.
 */
public data class KeyMaterial(val thresholdPublicKey: PublicKey, val secretShares: List<PrivateKey>, val publicShares: List<PublicKey>, val threshold: Int) {
    public val nParticipants: Int get() = publicShares.size

    init {
        require(secretShares.size == publicShares.size) { "secret and public shares count must match" }
        require(threshold in 1..nParticipants) { "invalid threshold" }
    }

    /**
     * Validate the key material (BIP 445 ValidateThresholdInfo): checks that the public shares lie on a single
     * polynomial and that they are consistent with the threshold public key. This does NOT validate the security
     * of the key generation that produced the key material.
     *
     * @return true if the key material is valid and consistent.
     */
    public fun isValid(): Boolean = try {
        Secp256k1.frostThresholdInfoValidate(thresholdPublicKey.value.toByteArray(), publicShares.map { it.value.toByteArray() }.toTypedArray(), threshold)
    } catch (_: Throwable) {
        false
    }

    /**
     * @param signerIds identifiers of the participants of a signing session.
     * @return the public shares of the given participants, in the same order as [signerIds].
     */
    public fun publicSharesOf(signerIds: List<UInt>): List<PublicKey> = signerIds.map { publicShares[it.toInt()] }

    /**
     * @return an opaque tweak cache for the (untweaked) threshold public key.
     */
    public fun tweakCache(): TweakCache = TweakCache.create(thresholdPublicKey)
}

/**
 * FROST tweak cache: keeps track of the threshold public key and the tweaks applied to it.
 * This should be treated as an opaque blob of data, that doesn't contain any sensitive data and thus can be stored.
 */
public data class TweakCache(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "frost tweak cache must be ${Secp256k1.FROST_TWEAK_CACHE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()

    /**
     * The current (tweaked) threshold public key: this is the public key that final signatures of sessions created
     * with this cache verify against.
     */
    public val tweakedPublicKey: XonlyPublicKey
        get() = XonlyPublicKey(Secp256k1.frostTweakedPubkeyGet(toByteArray()).byteVector32())

    /**
     * @param tweak tweak to apply.
     * @param isXonly true if the tweak is an x-only tweak (e.g. when using taproot).
     * @return an updated cache and the tweaked threshold public key, or an error if the tweak is invalid.
     */
    public fun tweak(tweak: ByteVector32, isXonly: Boolean): Either<Throwable, Pair<TweakCache, XonlyPublicKey>> = try {
        val localCache = toByteArray()
        val tweaked = if (isXonly) {
            Secp256k1.frostPubkeyXonlyTweakAdd(localCache, tweak.toByteArray())
        } else {
            Secp256k1.frostPubkeyEcTweakAdd(localCache, tweak.toByteArray())
        }
        Either.Right(Pair(TweakCache(localCache), XonlyPublicKey(tweaked.byteVector32())))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    public companion object {
        /**
         * @param thresholdPublicKey the (untweaked) threshold public key: callers must verify that it is valid.
         * @return an opaque tweak cache, which is required to create signing sessions (even if no tweaks are applied).
         */
        @JvmStatic
        public fun create(thresholdPublicKey: PublicKey): TweakCache {
            require(thresholdPublicKey.isValid()) { "the threshold public key provided is not valid" }
            return TweakCache(Secp256k1.frostTweakCacheInit(thresholdPublicKey.value.toByteArray()))
        }
    }
}

/**
 * FROST signing session context that can be used to create partial signatures and aggregate them.
 * The session is signer-agnostic: the same session can be used by the coordinator to verify the partial
 * signatures of all signers.
 */
public data class Session(private val data: ByteVector, val signerIds: List<UInt>, val signerPublicShares: List<PublicKey>?) {
    init {
        require(data.size() == Secp256k1.FROST_SESSION_SIZE) { "frost session must be ${Secp256k1.FROST_SESSION_SIZE} bytes" }
        require(signerIds.isNotEmpty()) { "signer ids must not be empty" }
        require(signerPublicShares == null || signerPublicShares.size == signerIds.size) { "public shares count must match signer ids count" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    /**
     * @param secretNonce signer's secret nonce (see [SecretNonce.generate]).
     * @param secretShare signer's secret share.
     * @param myId signer's identifier (must be one of [signerIds]).
     * @return a frost partial signature, or an error if the nonce has already been used or signing fails.
     */
    public fun sign(secretNonce: SecretNonce, secretShare: PrivateKey, myId: UInt): Either<Throwable, ByteVector32> =
        secretNonce.consume { nonce ->
            Secp256k1.frostSign(nonce, secretShare.value.toByteArray(), this.toByteArray(), signerIds.toUIntArray(), signerPublicShares?.map { it.value.toByteArray() }?.toTypedArray(), myId).byteVector32()
        }

    /**
     * @param partialSig frost partial signature.
     * @param publicNonce individual public nonce of the signing participant.
     * @param publicShare individual public share of the signing participant.
     * @param signerIndex index of the signer in the session's [signerIds].
     * @return true if the partial signature is valid.
     */
    public fun verify(partialSig: ByteVector32, publicNonce: IndividualNonce, publicShare: PublicKey, signerIndex: Int): Boolean = try {
        Secp256k1.frostPartialSigVerify(partialSig.toByteArray(), publicNonce.toByteArray(), publicShare.value.toByteArray(), this.toByteArray(), signerIds.toUIntArray(), signerIndex) == 1
    } catch (_: Throwable) {
        false
    }

    /**
     * Aggregate partial signatures from all signers into a single schnorr signature. Callers should verify the
     * resulting signature, which may be invalid without raising an error here (for example if the set of partial
     * signatures is valid but incomplete).
     *
     * @param partialSigs partial signatures of all signers (in the same order as [signerIds]).
     * @return the aggregate signature of all input partial signatures or an error if a partial signature is invalid.
     */
    public fun aggregateSigs(partialSigs: List<ByteVector32>): Either<Throwable, ByteVector64> = try {
        Either.Right(Secp256k1.frostPartialSigAgg(this.toByteArray(), partialSigs.map { it.toByteArray() }.toTypedArray()).byteVector64())
    } catch (t: Throwable) {
        Either.Left(t)
    }

    public companion object {
        /**
         * @param aggregatedNonce aggregated public nonce.
         * @param signerIds identifiers of the signing participants (each id must be unique and smaller than [nParticipants]).
         * @param signerPublicShares (optional) public shares of the signing participants (entry i belongs to
         * signerIds[i]). If provided, they are validated against the threshold public key, and each secret share is
         * checked against its public share when signing (recommended).
         * @param nParticipants total number of participants n.
         * @param threshold threshold t: the number of signers required to produce a signature.
         * @param tweakCache tweak cache holding the threshold public key and all tweaks applied to it.
         * @param message message that will be signed.
         * @return a frost signing session.
         */
        @JvmStatic
        public fun create(aggregatedNonce: AggregatedNonce, signerIds: List<UInt>, signerPublicShares: List<PublicKey>?, nParticipants: Int, threshold: Int, tweakCache: TweakCache, message: ByteVector): Session {
            val session = Secp256k1.frostSessionInit(aggregatedNonce.toByteArray(), signerIds.toUIntArray(), signerPublicShares?.map { it.value.toByteArray() }?.toTypedArray(), nParticipants, threshold, tweakCache.toByteArray(), message.toByteArray())
            return Session(session.byteVector(), signerIds, signerPublicShares)
        }
    }
}

/**
 * FROST secret nonce, that should be treated as a private opaque blob.
 * This nonce must never be persisted or reused across signing sessions: reusing it leaks the secret share.
 * Application code should use [generate] to create fresh nonces.
 */
@OptIn(ExperimentalAtomicApi::class)
public class SecretNonce private constructor(bytes: ByteArray, offset: Int, size: Int) {
    init {
        require(size == Secp256k1.FROST_SECRET_NONCE_SIZE) { "frost secret nonce must be ${Secp256k1.FROST_SECRET_NONCE_SIZE} bytes" }
        require(offset >= 0 && offset + size <= bytes.size) { "invalid secret nonce slice" }
    }

    internal val data: ByteArray = bytes.copyOfRange(offset, offset + size)

    internal constructor(bin: ByteArray) : this(bin, 0, bin.size)

    override fun toString(): String = "<secret_nonce>"

    private val consumed = AtomicBoolean(false)

    internal fun <T> consume(block: (ByteArray) -> T): Either<Throwable, T> {
        if (consumed.exchange(true)) return Either.Left(IllegalStateException("secret nonce has already been used"))
        return try {
            Either.Right(block(data))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecretNonce) return false
        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int = data.contentHashCode()

    public companion object {
        /**
         * Generate a secret nonce to be used in a frost signing session (BIP 445 NonceGen).
         * This nonce must never be persisted or reused across signing sessions.
         * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
         *
         * @param sessionRandom unique 32-byte random data that must not be reused to generate other nonces.
         * @param secretShare (optional) signer's secret share.
         * @param publicShare (optional) signer's public share: if provided along with [secretShare], they must match.
         * @param tweakedThresholdPublicKey (optional) tweaked threshold public key the signature will verify against
         * (see [TweakCache.tweakedPublicKey]).
         * @param message (optional) message that will be signed, if already known.
         * @param extraInput (optional) additional random data.
         * @return secret nonce and the corresponding public nonce.
         */
        @JvmStatic
        public fun generate(sessionRandom: ByteVector32, secretShare: PrivateKey?, publicShare: PublicKey?, tweakedThresholdPublicKey: XonlyPublicKey?, message: ByteVector?, extraInput: ByteVector32?): Pair<SecretNonce, IndividualNonce> {
            if (secretShare != null && publicShare != null) require(secretShare.publicKey() == publicShare) { "if the secret share is provided, it must match the public share" }
            val nonce = Secp256k1.frostNonceGen(sessionRandom.toByteArray(), secretShare?.value?.toByteArray(), publicShare?.value?.toByteArray(), tweakedThresholdPublicKey?.value?.toByteArray(), message?.toByteArray(), extraInput?.toByteArray())
            val secretNonce = SecretNonce(nonce, 0, Secp256k1.FROST_SECRET_NONCE_SIZE)
            val publicNonce = IndividualNonce(nonce.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, Secp256k1.FROST_SECRET_NONCE_SIZE + Secp256k1.FROST_PUBLIC_NONCE_SIZE))
            return Pair(secretNonce, publicNonce)
        }
    }
}

/**
 * FROST public nonce, that must be shared with the other signers of the signing session.
 * It contains two elliptic curve points, but should be treated as an opaque blob.
 */
public data class IndividualNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "individual frost public nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()

    public companion object {
        /**
         * Aggregate the public nonces of all signers of a signing session.
         * The nonce at index i must belong to the signer whose id is at index i in the signer ids of the session
         * (see [Session.create]). Returns an error if one of the nonces provided is invalid.
         */
        @JvmStatic
        public fun aggregate(nonces: List<IndividualNonce>): Either<Throwable, AggregatedNonce> = try {
            val agg = Secp256k1.frostNonceAgg(nonces.map { it.toByteArray() }.toTypedArray())
            Either.Right(AggregatedNonce(agg))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }
}

/**
 * FROST aggregate public nonce from all signers of a signing session.
 */
public data class AggregatedNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "aggregated frost public nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * This object contains helper functions to use frost in the context of spending taproot outputs.
 * In order to provide a simpler API, some operations are internally duplicated: if performance is an issue, you should
 * consider using the lower-level APIs directly (see [Session] and [TweakCache]).
 *
 * WARNING: the underlying secp256k1 FROST module is experimental and must not be used in production.
 */
public object Frost {
    /**
     * Generate FROST threshold key material with a trusted dealer (BIP 445).
     * The dealer must transmit each secret share to its participant over a secure channel and erase all secret
     * key material afterwards.
     *
     * WARNING: the underlying secp256k1 FROST module is experimental and must not be used in production.
     *
     * @param thresholdSecretKey threshold secret key.
     * @param nParticipants total number of participants n (at most [Secp256k1.FROST_MAX_PARTICIPANTS]).
     * @param threshold threshold t: the number of signers required to produce a signature.
     * @return the threshold key material.
     */
    @JvmStatic
    public fun trustedDealerKeygen(thresholdSecretKey: PrivateKey, nParticipants: Int, threshold: Int): KeyMaterial {
        val (thresholdPublicKey, secretShares, publicShares) = Secp256k1.frostTrustedDealerKeygen(thresholdSecretKey.value.toByteArray(), nParticipants, threshold)
        return KeyMaterial(PublicKey.parse(thresholdPublicKey), secretShares.map { PrivateKey(it) }, publicShares.map { PublicKey.parse(it) }, threshold)
    }

    /**
     * @param sessionRandom unique 32-byte random data that must not be reused to generate other nonces.
     * @param secretShare (optional) signer's secret share.
     * @param publicShare (optional) signer's public share: if provided along with [secretShare], they must match.
     * @param tweakedThresholdPublicKey (optional) tweaked threshold public key the signature will verify against.
     * @param message (optional) message that will be signed, if already known.
     * @param extraInput (optional) additional random data.
     * @return secret nonce and the corresponding public nonce.
     */
    @JvmStatic
    public fun generateNonce(sessionRandom: ByteVector32, secretShare: PrivateKey?, publicShare: PublicKey?, tweakedThresholdPublicKey: XonlyPublicKey?, message: ByteVector?, extraInput: ByteVector32?): Pair<SecretNonce, IndividualNonce> {
        return SecretNonce.generate(sessionRandom, secretShare, publicShare, tweakedThresholdPublicKey, message, extraInput)
    }

    @JvmStatic
    private fun signingSession(message: ByteVector, signerIds: List<UInt>, keyMaterial: KeyMaterial, tweakCache: TweakCache, publicNonces: List<IndividualNonce>): Either<Throwable, Session> {
        val signerPublicShares = try {
            keyMaterial.publicSharesOf(signerIds)
        } catch (t: Throwable) {
            return Either.Left(t)
        }
        return IndividualNonce.aggregate(publicNonces).map { aggregatedNonce ->
            Session.create(aggregatedNonce, signerIds, signerPublicShares, keyMaterial.nParticipants, keyMaterial.threshold, tweakCache, message)
        }
    }

    /**
     * Create a partial frost signature for the given arbitrary message.
     *
     * @param secretShare secret share of the signing participant.
     * @param secretNonce secret nonce of the signing participant.
     * @param myId identifier of the signing participant (must be one of [signerIds]).
     * @param message message that should be signed.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     * @return a partial signature, or an error if the nonce has already been used or session creation/signing fails.
     */
    @JvmStatic
    public fun sign(secretShare: PrivateKey, secretNonce: SecretNonce, myId: UInt, message: ByteVector, signerIds: List<UInt>, keyMaterial: KeyMaterial, publicNonces: List<IndividualNonce>): Either<Throwable, ByteVector32> {
        return signingSession(message, signerIds, keyMaterial, keyMaterial.tweakCache(), publicNonces).flatMap { session ->
            session.sign(secretNonce, secretShare, myId)
        }
    }

    /**
     * Verify a partial frost signature of an arbitrary message.
     *
     * @param partialSig partial frost signature.
     * @param nonce public nonce matching the secret nonce used to generate the signature.
     * @param publicShare public share of the signing participant.
     * @param signerIndex index of the signer in [signerIds].
     * @param message message signed.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     * @return true if the partial signature is valid.
     */
    @JvmStatic
    public fun verify(partialSig: ByteVector32, nonce: IndividualNonce, publicShare: PublicKey, signerIndex: Int, message: ByteVector, signerIds: List<UInt>, keyMaterial: KeyMaterial, publicNonces: List<IndividualNonce>): Boolean {
        return signingSession(message, signerIds, keyMaterial, keyMaterial.tweakCache(), publicNonces).map { session ->
            session.verify(partialSig, nonce, publicShare, signerIndex)
        }.getOrElse { false }
    }

    /**
     * Aggregate partial frost signatures into a valid schnorr signature for the given arbitrary message.
     *
     * @param partialSigs partial frost signatures of all signing participants (in the same order as [signerIds]).
     * @param message message signed.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     */
    @JvmStatic
    public fun aggregatePartialSignatures(partialSigs: List<ByteVector32>, message: ByteVector, signerIds: List<UInt>, keyMaterial: KeyMaterial, publicNonces: List<IndividualNonce>): Either<Throwable, ByteVector64> {
        return signingSession(message, signerIds, keyMaterial, keyMaterial.tweakCache(), publicNonces).flatMap { it.aggregateSigs(partialSigs) }
    }

    /**
     * Create a frost session for a given transaction input.
     *
     * @param tx transaction
     * @param inputIndex transaction input index
     * @param inputs outputs spent by this transaction
     * @param signerIds identifiers of the signing participants
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces signers' public nonces (in the same order as [signerIds])
     * @param scriptTree tapscript tree of the transaction's input, if it has script paths.
     */
    @JvmStatic
    public fun taprootSession(tx: Transaction, inputIndex: Int, inputs: List<TxOut>, signerIds: List<UInt>, keyMaterial: KeyMaterial, publicNonces: List<IndividualNonce>, scriptTree: ScriptTree?): Either<Throwable, Session> {
        val tweak = keyMaterial.thresholdPublicKey.xOnly().tweak(scriptTree?.hash()?.let { Crypto.TaprootTweak.ScriptPathTweak(it) } ?: Crypto.TaprootTweak.KeyPathTweak)
        return keyMaterial.tweakCache().tweak(tweak, isXonly = true).flatMap { (tweakedCache, _) ->
            val txHash = Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, inputs, SigHash.SIGHASH_DEFAULT)
            signingSession(txHash, signerIds, keyMaterial, tweakedCache, publicNonces)
        }
    }

    /**
     * Create a partial frost signature for the given taproot input key path.
     *
     * @param secretShare secret share of the signing participant.
     * @param secretNonce secret nonce of the signing participant.
     * @param myId identifier of the signing participant (must be one of [signerIds]).
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     * @return a partial signature, or an error if the nonce has already been used or session creation/signing fails.
     */
    @JvmStatic
    public fun signTaprootInput(
        secretShare: PrivateKey,
        secretNonce: SecretNonce,
        myId: UInt,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        signerIds: List<UInt>,
        keyMaterial: KeyMaterial,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Either<Throwable, ByteVector32> {
        return taprootSession(tx, inputIndex, inputs, signerIds, keyMaterial, publicNonces, scriptTree).flatMap { it.sign(secretNonce, secretShare, myId) }
    }

    /**
     * Verify a partial frost signature.
     *
     * @param partialSig partial frost signature.
     * @param nonce public nonce matching the secret nonce used to generate the signature.
     * @param publicShare public share of the signing participant.
     * @param signerIndex index of the signer in [signerIds].
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     * @return true if the partial signature is valid.
     */
    @JvmStatic
    public fun verify(
        partialSig: ByteVector32,
        nonce: IndividualNonce,
        publicShare: PublicKey,
        signerIndex: Int,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        signerIds: List<UInt>,
        keyMaterial: KeyMaterial,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Boolean {
        val session = taprootSession(tx, inputIndex, inputs, signerIds, keyMaterial, publicNonces, scriptTree)
        return session.map { it.verify(partialSig, nonce, publicShare, signerIndex) }.getOrElse { false }
    }

    /**
     * Aggregate partial frost signatures into a valid schnorr signature for the given taproot input key path.
     *
     * @param partialSigs partial frost signatures of all signing participants (in the same order as [signerIds]).
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param signerIds identifiers of the signing participants.
     * @param keyMaterial key material of the frost group: only its public data is used here.
     * @param publicNonces public nonces of the signing participants (in the same order as [signerIds]).
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     */
    @JvmStatic
    public fun aggregateTaprootSignatures(
        partialSigs: List<ByteVector32>,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        signerIds: List<UInt>,
        keyMaterial: KeyMaterial,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Either<Throwable, ByteVector64> {
        return taprootSession(tx, inputIndex, inputs, signerIds, keyMaterial, publicNonces, scriptTree).flatMap { it.aggregateSigs(partialSigs) }
    }

}
