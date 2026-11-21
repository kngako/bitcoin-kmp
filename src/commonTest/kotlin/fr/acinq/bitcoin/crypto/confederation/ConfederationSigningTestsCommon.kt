package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.Script
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.TestHelpers
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxIn
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.sat
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/**
 * Option A signing through [ConfederationSigning], one signer at a time, with only bytes between the parties. The
 * vectors are upstream's (zkp b5819301); the nonce randomness is deterministic so a failure reproduces, where a
 * real signer draws it fresh.
 */
class ConfederationSigningTestsCommon {
    private val vectors: JsonObject = TestHelpers.readResourceAsJson("confederation/vectors.json").jsonObject
    private fun hex(name: String): ByteVector = ByteVector(Hex.decode(vectors[name]!!.jsonPrimitive.content))
    private fun hex32(name: String): ByteVector32 = ByteVector32(hex(name))

    private val roster: ConfederationRoster = ConfederationRoster.fromData(hex("rpd")).right!!
    private val keyState: ConfederationKeyState = ConfederationKeyState.fromData(hex("ksd"), roster).right!!
    private fun hostSecret(i: Int): PrivateKey = PrivateKey(ByteArray(32).also { it[30] = 0x10; it[31] = (i + 1).toByte() })
    private val hostSecrets: Map<ConfederationRoleId, PrivateKey> = roster.roleIds.withIndex().associate { (i, id) -> id to hostSecret(i) }
    private val shares: Map<ConfederationRoleId, ConfederationShare> = run {
        val scalars = vectors["shares"]!!.jsonObject
        roster.roleIds.associateWith { role ->
            Confederation.wrapShare(role, PrivateKey.fromHex(scalars["(${role.groupId}, ${role.adminId})"]!!.jsonPrimitive.content), keyState).right!!
        }
    }
    private fun id(group: Int, admin: Int) = ConfederationRoleId(group.toUInt(), admin.toUInt())

    /** The vectors' selection: groups 0 and 1, admins 0 and 1 of the first, 0 and 2 of the second. */
    private val selection = ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 2u)))

    /** The vectors' three x-only tweaks, read back from their encoding. */
    private val tweaks: List<ConfederationTweak> = run {
        val encoded = hex("signing_tweak_sequence").toByteArray()
        val count = encoded[3].toInt()
        List(count) { i -> ConfederationTweak(ByteVector32(encoded.copyOfRange(4 + 33 * i, 4 + 33 * i + 32)), encoded[4 + 33 * i + 32].toInt() == 1) }
    }

    private var counter = 0
    private fun randomness(): ByteVector32 = ByteVector32(ByteArray(32).also { it[0] = 0x5e; it[1] = (++counter).toByte(); it[31] = 1 })

    private fun session(sessionId: ByteVector32 = hex32("signing_session_id"), sel: ConfederationSignerSelection = selection, tw: List<ConfederationTweak> = tweaks) =
        ConfederationSigningSession.create(keyState, sessionId, sel, tw).right!!

    private fun ConfederationNonceTranscript.wire() = ConfederationNonceTranscript(ByteVector(toByteArray()))
    private fun ConfederationConfirmationCertificate.wire() = ConfederationConfirmationCertificate(ByteVector(toByteArray()))
    private fun ConfederationGroupPartial.wire() = ConfederationGroupPartial(ByteVector(toByteArray()))

    /** Steps 1 to 8 with each signer building its own session: the signature, and each signer, spent. */
    private fun signAll(coordinator: ConfederationSigningSession, message: ByteVector32): Pair<ByteVector64, List<ConfederationSigner>> {
        val signers = coordinator.signers.map { role ->
            val own = ConfederationSigningSession.create(keyState, coordinator.sessionId, coordinator.selection, coordinator.tweaks).right!!
            assertTrue(own.check(ByteVector(coordinator.dSign.toByteArray())))
            ConfederationSigning.generateNonce(own, role, shares.getValue(role), randomness()).right!!
        }
        val transcript = ConfederationSigning.transcript(coordinator, signers.associate { it.role to ByteVector(it.publicNonce.toByteArray()) }).right!!
        val confirmations = signers.associate { it.role to ConfederationSigning.confirm(it, transcript.wire(), message, hostSecrets.getValue(it.role)).right!! }
        val certificate = ConfederationSigning.certificate(coordinator, transcript, message, confirmations).right!!
        assertTrue(ConfederationSigning.verifyCertificate(coordinator, transcript, message, certificate.wire()))
        val partials = signers.associate { it.role to ConfederationSigning.sign(it, shares.getValue(it.role), transcript.wire(), message, certificate.wire()).right!! }
        partials.forEach { (role, partial) -> assertTrue(ConfederationSigning.verifyMemberPartial(coordinator, transcript, message, certificate, role, partial)) }
        val groupPartials = coordinator.groups.associateWith { g ->
            val groupPartial = ConfederationSigning.aggregateGroup(coordinator, transcript, message, certificate, g, partials.filterKeys { it.groupId == g }).right!!
            assertEquals(g, groupPartial.groupId)
            assertTrue(ConfederationSigning.verifyGroup(coordinator, transcript, message, certificate, groupPartial.wire()))
            groupPartial.wire()
        }
        return ConfederationSigning.aggregate(coordinator, transcript, message, certificate, groupPartials).right!! to signers
    }

    @Test
    fun `signers on their own devices sign under the tweaked key`() {
        val coordinator = session()
        assertEquals(hex("d_sign"), coordinator.dSign)
        val message = hex32("message")
        val (sig, signers) = signAll(coordinator, message)
        assertTrue(Crypto.verifySignatureSchnorr(message, sig, XonlyPublicKey(PublicKey(hex("tweaked_Q")))))
        assertFalse(Crypto.verifySignatureSchnorr(message, sig, keyState.publicKey))
        signers.forEach { assertTrue(it.isSpent) }
    }

    @Test
    fun `signers on their own devices spend a taproot output`() {
        val internalKey = keyState.publicKey
        val funding = Transaction(2, listOf(), listOf(TxOut(50_000.sat(), Script.pay2tr(internalKey, Crypto.TaprootTweak.KeyPathTweak))), 0)
        val tx = Transaction(2, listOf(TxIn(OutPoint(funding, 0), sequence = TxIn.SEQUENCE_FINAL)), listOf(TxOut(49_000.sat(), Script.pay2wpkh(PrivateKey(ByteVector32.One).publicKey()))), 0)
        val (coordinator, message) = ConfederationSigning.taprootInputSession(keyState, ByteVector32(ByteArray(32) { 0x71 }), selection, tx, 0, funding.txOut, null).right!!
        val (sig, _) = signAll(coordinator, message)
        assertTrue(Crypto.verifySignatureSchnorr(message, sig, internalKey.outputKey(Crypto.TaprootTweak.KeyPathTweak).first))
        Transaction.correctlySpends(tx.updateWitness(0, Script.witnessKeyPathPay2tr(sig)), funding, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `a signer refuses another selection's D_sign`() {
        val own = session()
        val other = session(sel = ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 1u))))
        assertFalse(own.check(other.dSign))
        assertTrue(own.check(session().dSign))
    }

    @Test
    fun `a signer confirms once and signs once`() {
        val coordinator = session(ByteVector32(ByteArray(32) { 0x72 }))
        val message = ByteVector32(ByteArray(32) { 0x73 })
        val signers = coordinator.signers.map { ConfederationSigning.generateNonce(coordinator, it, shares.getValue(it), randomness()).right!! }
        val transcript = ConfederationSigning.transcript(coordinator, signers.associate { it.role to it.publicNonce }).right!!
        val first = signers[0]

        // A partial before confirmation is refused before it reaches the library.
        assertTrue(ConfederationSigning.sign(first, shares.getValue(first.role), transcript, message, ConfederationConfirmationCertificate(ByteVector(ByteArray(10)))).left is IllegalStateException)
        assertFalse(first.isSpent)

        val confirmations = signers.associate { it.role to ConfederationSigning.confirm(it, transcript, message, hostSecrets.getValue(it.role)).right!! }
        assertTrue(ConfederationSigning.confirm(first, transcript, message, hostSecrets.getValue(first.role)).left is IllegalStateException)
        val certificate = ConfederationSigning.certificate(coordinator, transcript, message, confirmations).right!!

        ConfederationSigning.sign(first, shares.getValue(first.role), transcript, message, certificate).right!!
        assertTrue(first.isSpent)
        assertTrue(ConfederationSigning.sign(first, shares.getValue(first.role), transcript, message, certificate).left is IllegalStateException)

        // A certificate for another message is refused, and the refusal spends the signer.
        val other = ByteVector32(ByteArray(32) { 0x74 })
        assertFalse(ConfederationSigning.verifyCertificate(coordinator, transcript, other, certificate))
        assertTrue(ConfederationSigning.sign(signers[1], shares.getValue(signers[1].role), transcript, other, certificate).isLeft)
        assertTrue(signers[1].isSpent)

        signers.forEach { it.abort() }
        signers.forEach { assertTrue(it.isSpent) }
    }

    @Test
    fun `a transcript without the signer's nonce is refused and spends it`() {
        val coordinator = session(ByteVector32(ByteArray(32) { 0x75 }))
        val message = ByteVector32(ByteArray(32) { 0x76 })
        val signers = coordinator.signers.map { ConfederationSigning.generateNonce(coordinator, it, shares.getValue(it), randomness()).right!! }
        val replacement = ConfederationSigning.generateNonce(coordinator, signers[0].role, shares.getValue(signers[0].role), randomness()).right!!
        val transcript = ConfederationSigning.transcript(coordinator, signers.associate { it.role to it.publicNonce } + (replacement.role to replacement.publicNonce)).right!!
        assertTrue(ConfederationSigning.confirm(signers[0], transcript, message, hostSecrets.getValue(signers[0].role)).isLeft)
        assertTrue(signers[0].isSpent)
        // The replacement, whose nonce is there, confirms.
        assertTrue(ConfederationSigning.confirm(replacement, transcript, message, hostSecrets.getValue(replacement.role)).isRight)
        (signers + replacement).forEach { it.abort() }
    }

    @Test
    fun `an aborted signer is spent`() {
        val coordinator = session(ByteVector32(ByteArray(32) { 0x77 }))
        val signer = ConfederationSigning.generateNonce(coordinator, id(0, 0), shares.getValue(id(0, 0)), randomness()).right!!
        assertFalse(signer.isSpent)
        assertTrue(signer.toString().contains("<secret>"))
        signer.abort()
        assertTrue(signer.isSpent)
        val transcript = ConfederationNonceTranscript(ByteVector(ByteArray(12 + 74 * 4)))
        assertTrue(ConfederationSigning.confirm(signer, transcript, ByteVector32.Zeroes, hostSecrets.getValue(id(0, 0))).left is IllegalStateException)
    }

    @Test
    fun `the caller's own mistakes raise`() {
        val coordinator = session(ByteVector32(ByteArray(32) { 0x78 }))
        // Not a selected signer; another role's share.
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.generateNonce(coordinator, id(2, 0), shares.getValue(id(2, 0)), randomness()) }
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.generateNonce(coordinator, id(0, 0), shares.getValue(id(0, 1)), randomness()) }
        val signers = coordinator.signers.map { ConfederationSigning.generateNonce(coordinator, it, shares.getValue(it), randomness()).right!! }
        // A nonce missing from the transcript; a transcript of the wrong size; another role's host key.
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.transcript(coordinator, signers.drop(1).associate { it.role to it.publicNonce }) }
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.confirm(signers[0], ConfederationNonceTranscript(ByteVector(ByteArray(10))), ByteVector32.Zeroes, hostSecrets.getValue(signers[0].role)) }
        val transcript = ConfederationSigning.transcript(coordinator, signers.associate { it.role to it.publicNonce }).right!!
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.confirm(signers[0], transcript, ByteVector32.Zeroes, hostSecret(8)) }
        // A group not selected; a group partial of the wrong size.
        assertFailsWith<IllegalArgumentException> { ConfederationSigning.aggregateGroup(coordinator, transcript, ByteVector32.Zeroes, ConfederationConfirmationCertificate(ByteVector.empty), 2u, emptyMap()) }
        assertFailsWith<IllegalArgumentException> { ConfederationGroupPartial(ByteVector(ByteArray(35))) }
        // A selection the roster does not allow.
        assertFailsWith<IllegalArgumentException> { ConfederationSigningSession.create(keyState, ByteVector32.Zeroes, ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u))), emptyList()) }
        signers.forEach { it.abort() }
    }
}
