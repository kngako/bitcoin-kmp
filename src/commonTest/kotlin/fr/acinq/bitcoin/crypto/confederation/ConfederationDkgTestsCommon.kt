package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.TestHelpers
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/**
 * The initial DKG through [ConfederationDkg], one role at a time. Between roles only `toByteArray()` crosses: every
 * message is rebuilt from bytes on the receiving side, as it would be off the wire. vectors.json is upstream's
 * (zkp b5819301), and the seeds are the vectors', so the ceremony lands on the vector key state and genesis.
 */
class ConfederationDkgTestsCommon {
    private val vectors: JsonObject = TestHelpers.readResourceAsJson("confederation/vectors.json").jsonObject
    private fun hex(name: String): ByteVector = ByteVector(Hex.decode(vectors[name]!!.jsonPrimitive.content))
    private fun hex32(name: String): ByteVector32 = ByteVector32(hex(name))

    private val roster: ConfederationRoster = ConfederationRoster.fromData(hex("rpd")).right!!
    private val sessionSeed = hex32("dkg_session_seed")

    private fun hostSecret(i: Int): PrivateKey = PrivateKey(ByteArray(32).also { it[30] = 0x10; it[31] = (i + 1).toByte() })
    private val hostSecrets: Map<ConfederationRoleId, PrivateKey> = roster.roleIds.withIndex().associate { (i, id) -> id to hostSecret(i) }
    private fun dealerSeed(i: Int) = ByteVector32(ByteArray(32).also { it[0] = 0xd0.toByte(); it[31] = (i + 1).toByte() })
    private fun recoveryNonce(i: Int) = ByteVector32(ByteArray(32).also { it[0] = 0x42; it[31] = (i + 1).toByte() })
    private fun id(group: Int, admin: Int) = ConfederationRoleId(group.toUInt(), admin.toUInt())

    /** A check that ran and found nobody at fault: a Right holding null, whose `right` is null too. */
    private fun assertNoFault(result: Either<Throwable, ConfederationFault?>) {
        assertTrue(result.isRight, "expected the check to run, got $result")
        assertNull(result.right)
    }

    /** The bytes of a message, as a receiver rebuilds it. */
    private fun ConfederationDealerRecord.wire() = ConfederationDealerRecord(ByteVector(toByteArray()))
    private fun ConfederationCiphertexts.wire() = ConfederationCiphertexts(ByteVector(toByteArray()))
    private fun ConfederationBroadcast.wire() = ConfederationBroadcast(ByteVector(toByteArray()))
    private fun ConfederationEvidenceList.wire() = ConfederationEvidenceList(ByteVector(toByteArray()))

    /** What each role keeps from step 1 on. */
    private class RoleStore(val record: ConfederationDealerRecord)

    private fun dealings(): Map<ConfederationRoleId, ConfederationDkgDealing> = roster.roleIds.withIndex().associate { (i, role) ->
        role to ConfederationDkg.participantStep1(roster, role, hostSecrets.getValue(role), dealerSeed(i), sessionSeed).right!!
    }

    private fun broadcastOf(dealings: Map<ConfederationRoleId, ConfederationDkgDealing>): ConfederationBroadcast {
        val received = dealings.mapValues { (_, d) -> ConfederationDkgDealing(d.record.wire(), d.ciphertexts.wire()) }
        val step = ConfederationDkg.coordinatorStep1(roster, sessionSeed, received).right!!
        assertNull(step.fault)
        return step.broadcast!!
    }

    @Test
    fun `nine roles reach the vector genesis with only bytes between them`() {
        val dealings = dealings()
        val stores = dealings.mapValues { (_, d) -> RoleStore(d.record) }
        assertEquals(hex("dkg_fixed_record_0"), dealings.getValue(id(0, 0)).record.data)
        val broadcast = broadcastOf(dealings)
        assertEquals(hex("dkg_fixed_broadcast"), broadcast.data)

        // Step 3: every role derives the key state itself and authorizes one genesis.
        val step2 = roster.roleIds.associateWith { role ->
            ConfederationDkg.participantStep2(roster, role, hostSecrets.getValue(role), sessionSeed, stores.getValue(role).record, broadcast.wire()).right!!
        }
        step2.values.forEach {
            assertNull(it.fault)
            assertEquals(hex32("dkg_fixed_transition_hash"), it.transitionHash)
        }
        val keyState = step2.getValue(id(0, 0)).keyState!!
        step2.values.forEach { assertEquals(keyState, it.keyState) }
        assertEquals(hex("dkg_fixed_ksd"), keyState.data)

        // Step 4: the coordinator collects and anyone can check the authorizations.
        val authorizations = ConfederationDkg.evidenceList(roster, step2.mapValues { it.value.authorization!! }).right!!
        assertEquals(hex("dkg_fixed_authorizations"), authorizations.data)
        assertNoFault(ConfederationDkg.verifyEvidence(roster, hex32("dkg_fixed_transition_hash"), ConfederationEvidencePurpose.AUTHORIZE, authorizations))

        // Step 5: every role, having stored what it must, acknowledges.
        val acknowledgments = roster.roleIds.associateWith { role ->
            val ack = ConfederationDkg.participantAcknowledge(roster, role, hostSecrets.getValue(role), step2.getValue(role).transitionHash!!, authorizations.wire()).right!!
            assertNull(ack.fault)
            ack.acknowledgment!!
        }
        val acknowledgmentList = ConfederationDkg.evidenceList(roster, acknowledgments).right!!
        assertEquals(hex("dkg_fixed_acknowledgments"), acknowledgmentList.data)

        // Step 6: the coordinator's own key state, and the certified genesis.
        val coordinatorKeyState = ConfederationDkg.deriveKeyState(roster, broadcast).right!!
        assertEquals(keyState, coordinatorKeyState)
        val finalized = ConfederationDkg.coordinatorFinalize(coordinatorKeyState, authorizations.wire(), acknowledgmentList.wire()).right!!
        assertNull(finalized.fault)
        val genesis = finalized.genesis!!
        assertEquals(hex("dkg_fixed_transition"), genesis.data)
        assertEquals(ConfederationOperation.Dkg, genesis.operation)

        // Step 7: every role's share, from what it stored. The one-process DKG agrees.
        val local = Confederation.dkgLocal(roster, sessionSeed, hostSecrets, roster.roleIds.withIndex().associate { (i, r) -> r to dealerSeed(i) }, roster.roleIds.withIndex().associate { (i, r) -> r to recoveryNonce(i) }).right!!
        assertEquals(local.keyState, keyState)
        assertEquals(local.genesis, genesis)
        roster.roleIds.withIndex().forEach { (i, role) ->
            val result = ConfederationDkg.participantFinalize(ConfederationTransition.fromData(genesis.data, null, keyState).right!!, keyState, role, hostSecrets.getValue(role), stores.getValue(role).record, broadcast.wire(), recoveryNonce(i)).right!!
            assertEquals(role, result.share.role)
            assertTrue(result.share.isValidFor(keyState))
            assertEquals(local.recoveries.getValue(role), result.recovery)
            assertFalse(result.toString().contains(Hex.encode(result.share.native)))
        }
        assertEquals(hex("dkg_fixed_recovery"), local.recoveries.getValue(id(0, 0)).data)
    }

    @Test
    fun `a role that restarts after the broadcast finishes with the same share`() {
        val dealings = dealings()
        val broadcast = broadcastOf(dealings)
        val role = id(1, 2)
        val record = ConfederationDealerRecord(ByteVector(dealings.getValue(role).record.toByteArray()))
        // Before the restart, and after it, from the stored record and broadcast alone.
        val before = ConfederationDkg.participantStep2(roster, role, hostSecrets.getValue(role), sessionSeed, record, broadcast).right!!
        val after = ConfederationDkg.participantStep2(roster, role, hostSecrets.getValue(role), sessionSeed, record.wire(), broadcast.wire()).right!!
        assertEquals(before.keyState, after.keyState)
        assertEquals(before.transitionHash, after.transitionHash)
        assertEquals(before.authorization, after.authorization)
        // And so does a dealer recomputing step 1 from its seed.
        assertEquals(dealings.getValue(role), ConfederationDkg.participantStep1(roster, role, hostSecrets.getValue(role), dealerSeed(5), sessionSeed).right!!)

        val keyState = after.keyState!!
        val genesis = Confederation.dkgLocal(roster, sessionSeed, hostSecrets, roster.roleIds.withIndex().associate { (i, r) -> r to dealerSeed(i) }, roster.roleIds.withIndex().associate { (i, r) -> r to recoveryNonce(i) }).right!!.genesis
        val first = ConfederationDkg.participantFinalize(genesis, keyState, role, hostSecrets.getValue(role), record, broadcast, recoveryNonce(5)).right!!
        val second = ConfederationDkg.participantFinalize(genesis, keyState, role, hostSecrets.getValue(role), record.wire(), broadcast.wire(), recoveryNonce(5)).right!!
        assertContentEquals(first.share.native, second.share.native)
        assertEquals(first.recovery, second.recovery)
    }

    @Test
    fun `faults name the role they implicate`() {
        val dealings = dealings()
        val bad = dealings.getValue(id(1, 0)).record.toByteArray().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val tampered = dealings + (id(1, 0) to dealings.getValue(id(1, 0)).copy(record = ConfederationDealerRecord(ByteVector(bad))))
        val step = ConfederationDkg.coordinatorStep1(roster, sessionSeed, tampered).right!!
        assertEquals(ConfederationFault(ConfederationFault.Kind.ROLE, id(1, 0)), step.fault)
        assertNull(step.broadcast)

        val broadcast = broadcastOf(dealings)
        val badRecord = ConfederationBroadcast(hex("dkg_fixed_broadcast_bad_record"))
        val role01 = ConfederationDkg.participantStep2(roster, id(0, 1), hostSecrets.getValue(id(0, 1)), sessionSeed, dealings.getValue(id(0, 1)).record, badRecord).right!!
        assertEquals(ConfederationFault(ConfederationFault.Kind.UNKNOWN, id(0, 0)), role01.fault)
        assertNull(role01.keyState)
        val role00 = ConfederationDkg.participantStep2(roster, id(0, 0), hostSecrets.getValue(id(0, 0)), sessionSeed, dealings.getValue(id(0, 0)).record, ConfederationBroadcast(hex("dkg_fixed_broadcast_replaced_own_record"))).right!!
        assertEquals(ConfederationFault.Kind.COORDINATOR, role00.fault?.kind)
        assertNull(role00.fault?.role)

        val step2 = roster.roleIds.associateWith { role ->
            ConfederationDkg.participantStep2(roster, role, hostSecrets.getValue(role), sessionSeed, dealings.getValue(role).record, broadcast).right!!
        }
        val hash = step2.getValue(id(0, 0)).transitionHash!!
        val authorizations = ConfederationDkg.evidenceList(roster, step2.mapValues { it.value.authorization!! }).right!!
        val flipped = authorizations.toByteArray().also { it[4 + 72 * 7 + 8 + 3] = (it[4 + 72 * 7 + 8 + 3].toInt() xor 1).toByte() }
        val ack = ConfederationDkg.participantAcknowledge(roster, id(0, 0), hostSecrets.getValue(id(0, 0)), hash, ConfederationEvidenceList(ByteVector(flipped))).right!!
        assertEquals(ConfederationFault(ConfederationFault.Kind.ROLE_OR_COORDINATOR, id(2, 1)), ack.fault)
        assertNull(ack.acknowledgment)
    }

    @Test
    fun `an investigation names the coordinator that tampered with a share`() {
        val dealings = dealings()
        val broadcast = broadcastOf(dealings)
        val tampered = ConfederationBroadcast(ByteVector(broadcast.toByteArray().also { val at = it.size - 9 * 32 + 31; it[at] = (it[at].toInt() xor 1).toByte() }))
        val role = id(0, 0)
        val step2 = ConfederationDkg.participantStep2(roster, role, hostSecrets.getValue(role), sessionSeed, dealings.getValue(role).record, tampered).right!!
        assertEquals(ConfederationFault.Kind.ROLE_OR_COORDINATOR, step2.fault?.kind)

        val responses = roster.roleIds.associateWith { dealer ->
            ConfederationDkg.investigationResponse(roster, sessionSeed, dealer, dealings.getValue(dealer).ciphertexts).right!!
        }
        assertEquals(ConfederationFault(ConfederationFault.Kind.COORDINATOR, null), ConfederationDkg.investigate(roster, role, hostSecrets.getValue(role), tampered, responses).right!!)
        assertNoFault(ConfederationDkg.investigate(roster, role, hostSecrets.getValue(role), broadcast, responses))
    }

    @Test
    fun `the caller's own mistakes raise`() {
        val dealings = dealings()
        // A host key that is not the role's.
        assertFailsWith<IllegalArgumentException> { ConfederationDkg.participantStep1(roster, id(0, 0), hostSecret(1), dealerSeed(0), sessionSeed) }
        // A role that is not in the roster.
        assertFailsWith<IllegalArgumentException> { ConfederationDkg.participantStep1(roster, id(3, 0), hostSecret(0), dealerSeed(0), sessionSeed) }
        // A dealing missing, or of the wrong size.
        assertFailsWith<IllegalArgumentException> { ConfederationDkg.coordinatorStep1(roster, sessionSeed, dealings - id(2, 2)) }
        val short = dealings + (id(0, 0) to dealings.getValue(id(0, 0)).copy(ciphertexts = ConfederationCiphertexts(ByteVector(ByteArray(10)))))
        assertFailsWith<IllegalArgumentException> { ConfederationDkg.coordinatorStep1(roster, sessionSeed, short) }
        assertFailsWith<IllegalArgumentException> { ConfederationDkg.evidenceList(roster, mapOf(id(0, 0) to ByteVector64.Zeroes)) }
        // What the library refuses comes back as a Left.
        assertTrue(ConfederationDkg.deriveKeyState(roster, ConfederationBroadcast(ByteVector(ByteArray(10)))).isLeft)
    }
}
