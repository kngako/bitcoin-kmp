@file:OptIn(kotlin.ExperimentalUnsignedTypes::class)

package fr.acinq.bitcoin.crypto.frost

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * Helper functions for prefractal, a nested FROST+MuSig2 scheme that lets a FROST t-of-n group stand in for a
 * single musig2 participant (see [fr.acinq.bitcoin.crypto.musig2.Musig2]). The group's threshold public key is
 * aggregated with the cosigners' keys with the usual musig2 key aggregation, and the group produces one ordinary
 * musig2 public nonce and partial signature per session, so cosigners cannot tell that a group is involved.
 *
 * A group signing session runs in two rounds:
 * 1. every participating member derives a nonce from its share and the session label (see [generateNonce]) and the
 *    nonces are combined (see [aggregateNonces]) into one ordinary musig2 public nonce, published to the
 *    cosigners. Because the nonces depend only on the share and the label, this round can run before the message
 *    is known,
 * 2. once the message is known, every member produces a signature share (see [partialSign]) and the shares are
 *    summed into one ordinary musig2 partial signature (see [aggregatePartialSignatures]).
 *
 * This is deliberately NOT [Frost]. The composition deviates from BIP 445 in three ways that only make sense
 * inside this nesting, all documented in the secp256k1 module's doc/prefractal.md:
 * - the nonce coefficient does not commit to the message, so that round one can run first; the outer musig2
 *   coefficient does commit to it and binds this one through the product,
 * - there is no frost-level key parity normalisation, because the threshold public key is an inner participant of
 *   the outer aggregation and is used as a full point,
 * - the frost tweak cache must be the identity; only the outer aggregate key is tweaked.
 *
 * Two rules the caller must follow, neither of which this API can enforce:
 * - ONE SESSION LABEL SIGNS ONE MESSAGE, group-wide. Nonces are a pure function of the share and the label, which
 *   is what lets a member re-derive in round two what it published in round one, and what lets a restarted signer
 *   reproduce a nonce it published earlier. The cost is that two different messages under one label leak the
 *   members' secret shares, with no error raised anywhere.
 * - THE ROUND-TWO SIGNERS MUST BE EXACTLY THE ROUND-ONE CONTRIBUTORS, not a subset. The Lagrange coefficients and
 *   the aggregate nonce are both defined over the participating set. Note this differs from
 *   [fr.acinq.bitcoin.crypto.iceberg.Iceberg], which does tolerate a round-two subset: iceberg interpolates over
 *   2t-1 contributions and FROST has no equivalent.
 *
 * WARNING: the underlying secp256k1 prefractal module is experimental ("neither the scheme nor this implementation
 * has been reviewed by anyone outside the project") and must not be used to protect anything of value.
 */
public object Prefractal {
    /** Domain separation for the per-member nonce label, distinct from any other scheme's. */
    private const val SESSION_TAG: String = "Prefractal/session"

    /**
     * Derive a member's nonce deterministically from a session label.
     *
     * The randomness handed to nonce generation is `sha256("Prefractal/session" || sessionId || ser32(myId))`, so
     * the nonce is a pure function of the member's share and the label. That is what lets round two re-derive what
     * round one published without storing anything between them, and what lets a freshly constructed signer
     * reproduce a nonce it published before it was restarted.
     *
     * The message is deliberately NOT mixed in: the group's wire nonce is published before the message exists.
     * [Frost.deterministicSign] is unusable here for the same reason.
     *
     * @param secretShare the member's secret share.
     * @param publicShare the member's public share; checked against [secretShare].
     * @param groupPublicKey the group's untweaked threshold public key.
     * @param sessionId 32-byte session label: public, need not be random, but MUST never be used twice by the
     * group. See the note on this object.
     * @param myId the member's identifier.
     */
    @JvmStatic
    public fun generateNonce(secretShare: PrivateKey, publicShare: PublicKey, groupPublicKey: PublicKey, sessionId: ByteVector32, myId: UInt): Pair<SecretNonce, IndividualNonce> {
        val label = Crypto.sha256(SESSION_TAG.encodeToByteArray() + sessionId.toByteArray() + ser32(myId))
        // The group key is passed x-only because that is what the frost nonce-generation binding accepts. It is
        // only extra domain separation there, and the label above already provides it: iceberg's equivalent takes
        // no group key at all.
        return Frost.generateNonce(ByteVector32(label), secretShare, publicShare, groupPublicKey.xOnly(), null, null)
    }

    /**
     * Combine the members' public nonces into the group's wire nonce.
     *
     * @param publicNonces the participating members' public nonces (see [generateNonce]).
     * @param signerIds the participating members' identifiers; entry i belongs to publicNonces[i], all distinct.
     * This set fixes the session: [partialSign] must be given the same one.
     * @param groupPublicKey the group's untweaked threshold public key.
     * @return an ordinary musig2 public nonce to publish to the cosigners, and the UNSCALED frost aggregate nonce,
     * which is an internal value that must be handed back to [partialSign] and [verifyPartialSignature] unchanged.
     */
    @JvmStatic
    public fun aggregateNonces(publicNonces: List<IndividualNonce>, signerIds: List<UInt>, groupPublicKey: PublicKey): Either<Throwable, Pair<fr.acinq.bitcoin.crypto.musig2.IndividualNonce, AggregatedNonce>> = try {
        val (wire, unscaled) = Secp256k1.prefractalNonceAgg(
            publicNonces.map { it.toByteArray() }.toTypedArray(),
            signerIds.toUIntArray(),
            groupPublicKey.toUncompressedBin()
        )
        Either.Right(Pair(fr.acinq.bitcoin.crypto.musig2.IndividualNonce(wire), AggregatedNonce(unscaled)))
    } catch (e: Throwable) {
        Either.Left(e)
    }

    /**
     * Produce a member's signature share.
     *
     * The secret nonce is consumed: a second call with the same one fails. Note that the nonce is a pure function
     * of the share and the session label, so re-deriving it with [generateNonce] and signing a DIFFERENT message
     * leaks the secret share. See the note on this object.
     *
     * @param secretNonce the member's secret nonce (see [generateNonce]).
     * @param secretShare the member's secret share.
     * @param myId the member's identifier; must be one of [signerIds].
     * @param signerIds the participating members' identifiers, the same set given to [aggregateNonces].
     * @param signerPublicShares the participating members' public shares, in the order of [signerIds].
     * @param groupAggregatedNonce the unscaled frost aggregate nonce from [aggregateNonces].
     * @param groupPublicKey the group's untweaked threshold public key.
     * @param tweakCache the group's frost tweak cache, which must be the identity: only the outer aggregate key is
     * tweaked in this composition.
     * @param keyAggCache the OUTER musig2 key aggregation cache, already carrying any BIP341 tweak.
     * @param message the message being signed.
     * @param cosignerAggregatedNonce the aggregate of the NON-group participants' musig2 public nonces.
     */
    @JvmStatic
    public fun partialSign(
        secretNonce: SecretNonce,
        secretShare: PrivateKey,
        myId: UInt,
        signerIds: List<UInt>,
        signerPublicShares: List<PublicKey>,
        groupAggregatedNonce: AggregatedNonce,
        groupPublicKey: PublicKey,
        tweakCache: TweakCache,
        keyAggCache: KeyAggCache,
        message: ByteVector32,
        cosignerAggregatedNonce: fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
    ): Either<Throwable, ByteVector32> = secretNonce.consume { nonce ->
        ByteVector32(
            Secp256k1.prefractalSign(
                nonce,
                secretShare.value.toByteArray(),
                myId,
                signerIds.toUIntArray(),
                signerPublicShares.map { it.value.toByteArray() }.toTypedArray(),
                groupAggregatedNonce.toByteArray(),
                groupPublicKey.toUncompressedBin(),
                tweakCache.toByteArray(),
                keyAggCache.toByteArray(),
                cosignerAggregatedNonce.toByteArray(),
                message.toByteArray()
            )
        )
    }

    /**
     * Verify one member's signature share, to name the member at fault when the aggregate does not verify.
     *
     * Every session parameter must be the one [partialSign] was given.
     *
     * @param partialSig the signature share to verify.
     * @param publicNonce the member's public nonce, as given to [aggregateNonces].
     * @param publicShare the member's public share.
     */
    @JvmStatic
    public fun verifyPartialSignature(
        partialSig: ByteVector32,
        publicNonce: IndividualNonce,
        publicShare: PublicKey,
        myId: UInt,
        signerIds: List<UInt>,
        groupAggregatedNonce: AggregatedNonce,
        groupPublicKey: PublicKey,
        tweakCache: TweakCache,
        keyAggCache: KeyAggCache,
        message: ByteVector32,
        cosignerAggregatedNonce: fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
    ): Boolean = try {
        Secp256k1.prefractalPartialSigVerify(
            partialSig.toByteArray(),
            publicNonce.toByteArray(),
            publicShare.value.toByteArray(),
            myId,
            signerIds.toUIntArray(),
            groupAggregatedNonce.toByteArray(),
            groupPublicKey.toUncompressedBin(),
            tweakCache.toByteArray(),
            keyAggCache.toByteArray(),
            cosignerAggregatedNonce.toByteArray(),
            message.toByteArray()
        ) == 1
    } catch (e: Throwable) {
        false
    }

    /**
     * Sum the members' signature shares into one ordinary musig2 partial signature, ready to be aggregated with
     * the cosigners' by [fr.acinq.bitcoin.crypto.musig2.Musig2.aggregateSigs].
     *
     * @param partialSigs the participating members' signature shares (see [partialSign]).
     * @param tweakCache the group's frost tweak cache, which must be the identity.
     */
    @JvmStatic
    public fun aggregatePartialSignatures(partialSigs: List<ByteVector32>, tweakCache: TweakCache): Either<Throwable, ByteVector32> = try {
        Either.Right(ByteVector32(Secp256k1.prefractalPartialSigAgg(partialSigs.map { it.toByteArray() }.toTypedArray(), tweakCache.toByteArray())))
    } catch (e: Throwable) {
        Either.Left(e)
    }

    /** Big-endian serialization of a member identifier, matching the C module's ser32. */
    private fun ser32(v: UInt): ByteArray = byteArrayOf(
        (v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte()
    )
}
