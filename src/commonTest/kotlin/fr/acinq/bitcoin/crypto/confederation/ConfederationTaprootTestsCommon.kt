package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/**
 * A confederation key as a taproot internal key: a P2TR output, with or without script paths, spent through its key
 * path by a confederation signature, and checked by the script interpreter.
 *
 * Deterministic seeds so that a failure reproduces. Real callers must use fresh randomness.
 */
class ConfederationTaprootTestsCommon {
    private val roster: ConfederationRoster = run {
        val vectors = TestHelpers.readResourceAsJson("confederation/vectors.json").jsonObject
        ConfederationRoster.fromData(ByteVector(Hex.decode(vectors["rpd"]!!.jsonPrimitive.content))).right!!
    }

    private fun seed(tag: Int, i: Int) = ByteVector32(ByteArray(32).also { it[0] = tag.toByte(); it[31] = (i + 1).toByte() })

    private val hostSecrets = roster.roleIds.withIndex().associate { (i, id) -> id to PrivateKey(ByteArray(32).also { it[30] = 0x10; it[31] = (i + 1).toByte() }) }

    private val dkg: ConfederationDkgOutput = Confederation.dkgLocal(
        roster,
        seed(0x5e, 0),
        hostSecrets,
        roster.roleIds.withIndex().associate { (i, id) -> id to seed(0xd0, i) },
        roster.roleIds.withIndex().associate { (i, id) -> id to seed(0x42, i) },
    ).right!!

    private val internalKey: XonlyPublicKey = dkg.keyState.publicKey

    /** Deterministic nonce randomness for [selection]'s signers, distinct per [tag]. Real callers draw it fresh. */
    private fun nonces(selection: ConfederationSignerSelection, tag: Int): Map<ConfederationRoleId, ByteVector32> =
        selection.signers.associateWith { r -> ByteVector32(ByteArray(32).also { it[0] = 0x4d; it[1] = tag.toByte(); it[30] = r.groupId.toByte(); it[31] = r.adminId.toByte() }) }

    /** Groups 0 and 2: admins 0 and 2 of the first, 1 and 2 of the second. */
    private val selection = ConfederationSignerSelection(mapOf(0u to setOf(0u, 2u), 2u to setOf(1u, 2u)))

    private fun fund(pubkeyScript: List<ScriptElt>) = Transaction(2, listOf(), listOf(TxOut(50_000.sat(), pubkeyScript)), 0)

    private fun spend(funding: Transaction) = Transaction(
        2,
        listOf(TxIn(OutPoint(funding, 0), sequence = TxIn.SEQUENCE_FINAL)),
        listOf(TxOut(49_000.sat(), Script.pay2wpkh(PrivateKey(ByteVector32.One).publicKey()))),
        0,
    )

    private fun signedSpend(funding: Transaction, scriptTree: ScriptTree?, session: Int): Transaction {
        val tx = spend(funding)
        val sig = Confederation.signTaprootInputLocal(dkg.keyState, dkg.shares, hostSecrets, selection, tx, 0, funding.txOut, scriptTree, seed(0x7a, session), nonces(selection, 0x7a + session)).right!!
        return tx.updateWitness(0, Script.witnessKeyPathPay2tr(sig))
    }

    @Test
    fun `the taproot tweak signs for the BIP 341 output key`() {
        listOf(Crypto.TaprootTweak.KeyPathTweak, Crypto.TaprootTweak.ScriptPathTweak(ByteVector32(ByteArray(32) { 7 }))).forEachIndexed { i, tapTweak ->
            val message = seed(0x99, i)
            val sig = Confederation.signLocal(dkg.keyState, dkg.shares, hostSecrets, selection, listOf(ConfederationTweak.taproot(internalKey, tapTweak)), seed(0x7b, i), message, nonces(selection, 0x7b + i)).right!!
            assertTrue(Crypto.verifySignatureSchnorr(message, sig, internalKey.outputKey(tapTweak).first))
            assertFalse(Crypto.verifySignatureSchnorr(message, sig, internalKey))
        }
    }

    @Test
    fun `spend a key-path-only output`() {
        val funding = fund(Script.pay2tr(internalKey, Crypto.TaprootTweak.KeyPathTweak))
        Transaction.correctlySpends(signedSpend(funding, scriptTree = null, session = 0), funding, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `spend the key path of an output with a script tree`() {
        val refundKey = PrivateKey(ByteArray(32) { 3 })
        val scriptTree = ScriptTree.Leaf(listOf(OP_PUSHDATA(refundKey.xOnlyPublicKey()), OP_CHECKSIGVERIFY, OP_PUSHDATA(Script.encodeNumber(25920)), OP_CHECKSEQUENCEVERIFY))
        val funding = fund(Script.pay2tr(internalKey, scriptTree))
        Transaction.correctlySpends(signedSpend(funding, scriptTree, session = 1), funding, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        // Signing as if there were no script path tweaks to the wrong output key.
        assertFails { Transaction.correctlySpends(signedSpend(funding, scriptTree = null, session = 2), funding, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
    }
}
