package fr.acinq.bitcoin.crypto.iceberg

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.AggregatedNonce
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.KeyAggCache
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

/**
 * Iceberg share of a member of a threshold group (see [Iceberg.dealShares]).
 * This is sensitive data that must be stored securely: it contains everything the member needs to participate in
 * signing sessions.
 */
public data class Share(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        // A share is made of a 4-byte header followed by 32-byte seeds.
        require(data.size() in 36..Secp256k1.ICEBERG_SHARE_MAX_SIZE && (data.size() - 4) % 32 == 0) { "invalid iceberg share size" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    /** We avoid accidentally logging shares: use [toByteArray] to explicitly serialize a share. */
    override fun toString(): String = "<iceberg_share>"
}

/**
 * Iceberg share cache: the Lagrange weights derived from a member's share (see [Iceberg.shareCache]).
 * This is an opaque optimization blob: it contains no secret material, but has no serialized form and should be
 * rebuilt from the share rather than persisted.
 */
public data class ShareCache(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) { "iceberg share cache must be ${Secp256k1.ICEBERG_SHARE_CACHE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * Iceberg public key share of a member of a threshold group (see [Iceberg.publicShare]), meant to be published.
 * This should be treated as an opaque blob.
 */
public data class PublicShare(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE) { "iceberg public share must be ${Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * Iceberg nonce contribution of a member of a threshold group (see [Iceberg.generateNonce]), to publish to the
 * other group members. This should be treated as an opaque blob.
 */
public data class NonceContribution(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "iceberg nonce contribution must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * Iceberg signature share of a member of a threshold group (see [Iceberg.partialSign]), to publish to the other
 * group members. This should be treated as an opaque blob.
 */
public data class SignatureShare(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.ICEBERG_PARTIAL_SIG_SIZE) { "iceberg signature share must be ${Secp256k1.ICEBERG_PARTIAL_SIG_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * This object contains helper functions for Iceberg, a threshold scheme that lets a group of n parties stand in
 * for a single musig2 participant (see [fr.acinq.bitcoin.crypto.musig2.Musig2]). The group's public key (see
 * [groupPublicKey]) is aggregated with the cosigners' keys with the usual musig2 key aggregation, and the group
 * produces one ordinary musig2 public nonce and partial signature per signing session, so cosigners cannot tell
 * that a group is involved. The quorum is 2t-1 group members out of n.
 *
 * A group signing session runs in two rounds:
 * 1. a quorum of members publishes its nonce contribution (see [generateNonce]): these contributions depend only
 *    on the member's share and the session label, so this round can run before the message is known. The
 *    contributions are combined into one ordinary musig2 public nonce (see [aggregateNonces]) that is published
 *    to the cosigners,
 * 2. once the message is known, a quorum of members publishes its signature share (see [partialSign]): at least t
 *    shares are combined into one ordinary musig2 partial signature (see [aggregatePartialSignatures]) that is
 *    published to the cosigners.
 *
 * WARNING: the underlying secp256k1 Iceberg module is experimental ("neither the scheme nor this implementation
 * has been reviewed by anyone outside the project") and must not be used to protect anything of value.
 */
public object Iceberg {
    /**
     * Deal the shares of an Iceberg group from a single seed (trusted dealer).
     *
     * WARNING: a trusted dealer momentarily holds everything needed to reconstruct the group's private key; the
     * seed must be erased afterwards.
     *
     * @param n number of participants (at most [Secp256k1.ICEBERG_MAX_PARTICIPANTS]).
     * @param t threshold: the quorum is 2t-1 participants, so t must be at most (n+1)/2 (2-of-2 and 3-of-4 are
     * inexpressible; 2-of-4 is the smallest usable group).
     * @param seed 32 bytes of uniformly random data.
     * @return the share of each participant (entry k belongs to participant k).
     */
    @JvmStatic
    public fun dealShares(n: Int, t: Int, seed: ByteVector32): List<Share> {
        return Secp256k1.icebergSharesGen(n, t, seed.toByteArray()).map { Share(it) }
    }

    /**
     * Derive the Lagrange weights cache for a share (an optimization: [publicShare], [generateNonce] and
     * [partialSign] recompute them when no cache is provided).
     *
     * @param share the member's share (see [dealShares]).
     * @return the share cache: rebuild it from the share rather than persisting it.
     */
    @JvmStatic
    public fun shareCache(share: Share): ShareCache {
        return ShareCache(Secp256k1.icebergShareCacheCreate(share.toByteArray()))
    }

    /**
     * Compute a member's public key share.
     *
     * @param share the member's share.
     * @param cache (optional) the member's share cache (see [shareCache]).
     * @return the member's public key share, meant to be published.
     */
    @JvmStatic
    public fun publicShare(share: Share, cache: ShareCache?): PublicShare {
        return PublicShare(Secp256k1.icebergPubshareGen(share.toByteArray(), cache?.toByteArray()))
    }

    /**
     * Verify the members' public key shares and combine them into the group's public key.
     *
     * @param publicShares public key shares of the members (at least 2t-1, at most n).
     * @param n group size the shares were dealt for.
     * @param t threshold.
     * @return the group's public key, to be aggregated with the cosigners' keys with the usual musig2 key
     * aggregation (see [KeyAggCache.create]) exactly as if it belonged to a single signer.
     */
    @JvmStatic
    public fun groupPublicKey(publicShares: List<PublicShare>, n: Int, t: Int): Either<Throwable, PublicKey> = try {
        Either.Right(PublicKey.parse(Secp256k1.icebergPubkeyAgg(publicShares.map { it.toByteArray() }.toTypedArray(), n, t)))
    } catch (e: Throwable) {
        Either.Left(e)
    }

    /**
     * Derive a member's nonce contribution for a signing session. It depends only on the share and the session
     * label, so this round can run before the message exists, and there is no secret nonce to keep between the two
     * rounds.
     *
     * @param share the member's share.
     * @param cache (optional) the member's share cache.
     * @param sessionId 32-byte session label: public, need not be random, but must never be used twice by the group.
     * @return the member's nonce contribution, to publish to the other group members.
     */
    @JvmStatic
    public fun generateNonce(share: Share, cache: ShareCache?, sessionId: ByteVector32): NonceContribution {
        return NonceContribution(Secp256k1.icebergNonceGen(share.toByteArray(), cache?.toByteArray(), sessionId.toByteArray()))
    }

    /**
     * Verify the group members' nonce contributions and combine them into one ordinary musig2 public nonce.
     * From that nonce upwards, signing is plain musig2.
     *
     * @param nonceContributions nonce contributions of a quorum of members (at least 2t-1, at most n).
     * @param n group size.
     * @param t threshold.
     * @param groupPublicKey the group's public key (see [groupPublicKey]).
     * @return a musig2 public nonce, to publish to the cosigners.
     */
    @JvmStatic
    public fun aggregateNonces(nonceContributions: List<NonceContribution>, n: Int, t: Int, groupPublicKey: PublicKey): Either<Throwable, IndividualNonce> = try {
        Either.Right(IndividualNonce(Secp256k1.icebergNonceAgg(nonceContributions.map { it.toByteArray() }.toTypedArray(), n, t, groupPublicKey.toUncompressedBin())))
    } catch (e: Throwable) {
        Either.Left(e)
    }

    /**
     * Check that a musig2 key aggregation cache aggregates exactly the given list of public keys, in this order,
     * and that the group's public key is one of them. Run this once where the cache is built: signing with a cache
     * built over a different key set spends the session label on a useless signature share.
     *
     * @param keyAggCache the outer musig2 key aggregation cache (see [KeyAggCache.create]).
     * @param publicKeys the keys the cache should have been built from, in the order they were passed to
     * [KeyAggCache.create].
     * @param groupPublicKey the group's public key, which must be one of [publicKeys].
     * @return true if the cache aggregates exactly this key list and contains the group's public key.
     */
    @JvmStatic
    public fun keyAggregationCheck(keyAggCache: KeyAggCache, publicKeys: List<PublicKey>, groupPublicKey: PublicKey): Boolean = try {
        Secp256k1.icebergKeyaggCheck(keyAggCache.toByteArray(), publicKeys.map { it.value.toByteArray() }.toTypedArray(), groupPublicKey.toUncompressedBin())
    } catch (_: Throwable) {
        false
    }

    /**
     * Produce a member's signature share.
     *
     * Never call this twice with the same [sessionId], whatever else changes: a member's secrets are fixed by the
     * label alone, so two answers under one label leak the share by elimination. Callers must durably record the
     * labels they have answered under.
     *
     * @param share the member's share.
     * @param cache (optional) the member's share cache.
     * @param sessionId the session label, the same one [generateNonce] used.
     * @param nonceContributions the group's own nonce contributions (at least 2t-1; any qualifying set from the
     * session gives the same result).
     * @param groupPublicKey the group's public key (the one [aggregateNonces] was given).
     * @param keyAggCache the outer musig2 key aggregation cache (see [keyAggregationCheck]).
     * @param message 32-byte message being signed.
     * @param cosignerAggregatedNonce the cosigners' aggregate nonce, theirs alone (see [IndividualNonce.aggregate]).
     * @return the member's signature share, to publish to the other group members.
     */
    @JvmStatic
    public fun partialSign(share: Share, cache: ShareCache?, sessionId: ByteVector32, nonceContributions: List<NonceContribution>, groupPublicKey: PublicKey, keyAggCache: KeyAggCache, message: ByteVector32, cosignerAggregatedNonce: AggregatedNonce): Either<Throwable, SignatureShare> = try {
        Either.Right(SignatureShare(Secp256k1.icebergPartialSign(share.toByteArray(), cache?.toByteArray(), sessionId.toByteArray(), nonceContributions.map { it.toByteArray() }.toTypedArray(), groupPublicKey.toUncompressedBin(), keyAggCache.toByteArray(), message.toByteArray(), cosignerAggregatedNonce.toByteArray())))
    } catch (e: Throwable) {
        Either.Left(e)
    }

    /**
     * Check one member's signature share against what its author published. A false result means the share does not
     * satisfy the signing equation against these inputs: it does not distinguish a bad share from bad inputs, and
     * does not name a culprit.
     *
     * @param signatureShare signature share to check.
     * @param publicShare public key share of the member the signature share is attributed to.
     * @param nonceContributions a qualifying set of nonce contributions from the same session (at least 2t-1).
     * @param n group size.
     * @param t threshold.
     * @param groupPublicKey the group's public key.
     * @param keyAggCache the outer musig2 key aggregation cache.
     * @param message 32-byte message being signed.
     * @param cosignerAggregatedNonce the cosigners' aggregate nonce.
     * @return true if the signature share is valid.
     */
    @JvmStatic
    public fun verifyPartialSignature(signatureShare: SignatureShare, publicShare: PublicShare, nonceContributions: List<NonceContribution>, n: Int, t: Int, groupPublicKey: PublicKey, keyAggCache: KeyAggCache, message: ByteVector32, cosignerAggregatedNonce: AggregatedNonce): Boolean = try {
        Secp256k1.icebergPartialSigVerify(signatureShare.toByteArray(), publicShare.toByteArray(), nonceContributions.map { it.toByteArray() }.toTypedArray(), n, t, groupPublicKey.toUncompressedBin(), keyAggCache.toByteArray(), message.toByteArray(), cosignerAggregatedNonce.toByteArray()) == 1
    } catch (_: Throwable) {
        false
    }

    /**
     * Combine signature shares into one ordinary musig2 partial signature, to be aggregated with the cosigners'
     * partial signatures (see [fr.acinq.bitcoin.crypto.musig2.Session.aggregateSigs]). Given more than t shares, a
     * self-contradicting set is refused.
     *
     * @param signatureShares signature shares (at least t, at most n).
     * @param n group size.
     * @param t threshold.
     * @return a musig2 partial signature.
     */
    @JvmStatic
    public fun aggregatePartialSignatures(signatureShares: List<SignatureShare>, n: Int, t: Int): Either<Throwable, ByteVector32> = try {
        Either.Right(Secp256k1.icebergPartialSigAgg(signatureShares.map { it.toByteArray() }.toTypedArray(), n, t).byteVector32())
    } catch (e: Throwable) {
        Either.Left(e)
    }
}
