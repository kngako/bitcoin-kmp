package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.TestHelpers
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.bitcoin.byteVector
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/**
 * Confederation through the bitcoin-kmp wrapper.
 *
 * The bytes are pinned by secp256k1-kmp's own binding tests and vectors; vectors.json is copied from secp256k1-kmp
 * fce4d81 (zkp confederation e18a8e8e). What is exercised here is what this layer adds: the roster read from its
 * canonical encoding, per-role inputs keyed by role and ordered by the wrapper, the caller's errors raised as
 * [IllegalArgumentException] rather than returned, canonical signer selection and tweak encoding, typed transitions
 * and recovery packages, and secrets kept out of [toString].
 *
 * Every seed, nonce and session identifier here is deterministic so that a failure reproduces. Real callers must
 * use fresh randomness.
 */
class ConfederationTestsCommon {
    private val vectors: JsonObject = TestHelpers.readResourceAsJson("confederation/vectors.json").jsonObject

    private fun hex(name: String): ByteVector = ByteVector(Hex.decode(vectors[name]!!.jsonPrimitive.content))

    private fun hex32(name: String): ByteVector32 = ByteVector32(hex(name).also { assertEquals(32, it.size()) })

    private val roster: ConfederationRoster = ConfederationRoster.fromData(hex("rpd")).right!!
    private val keyState: ConfederationKeyState = ConfederationKeyState.fromData(hex("ksd"), roster).right!!

    /** The vectors' host secret key for the role at flattened index [i]. */
    private fun hostSecret(i: Int): PrivateKey = PrivateKey(ByteArray(32).also { it[30] = 0x10; it[31] = (i + 1).toByte() })

    private fun byRole(f: (Int) -> ByteVector32): Map<ConfederationRoleId, ByteVector32> = roster.roleIds.withIndex().associate { (i, id) -> id to f(i) }

    private val hostSecrets: Map<ConfederationRoleId, PrivateKey> = roster.roleIds.withIndex().associate { (i, id) -> id to hostSecret(i) }
    private val dealerSeeds = byRole { i -> ByteVector32(ByteArray(32).also { it[0] = 0xd0.toByte(); it[31] = (i + 1).toByte() }) }
    private val recoveryNonces = byRole { i -> ByteVector32(ByteArray(32).also { it[0] = 0x42; it[31] = (i + 1).toByte() }) }

    private fun dkg(sessionSeed: ByteVector32 = hex32("dkg_session_seed")): ConfederationDkgOutput =
        Confederation.dkgLocal(roster, sessionSeed, hostSecrets, dealerSeeds, recoveryNonces).right!!

    private fun id(group: Int, admin: Int) = ConfederationRoleId(group.toUInt(), admin.toUInt())

    private fun session(tag: Int) = ByteVector32(ByteArray(32).also { it[0] = tag.toByte() })

    /** Groups 0 and 1, admins 0 and 1 of each: the smallest authorized coalition of the vectors' 2-of-(2-of-3) roster. */
    private val twoByTwo = ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 1u)))

    /** The offset of the entity id of the role at flattened index [i], in a roster of 3-role groups. */
    private fun entityOffset(i: Int): Int = 96 + (i / 3 + 1) * 20 + i * 69 + 4

    private fun withSharedEntity(data: ByteVector, target: Int, source: Int): ByteVector {
        val bytes = data.toByteArray()
        bytes.copyInto(bytes, entityOffset(target), entityOffset(source), entityOffset(source) + 32)
        return ByteVector(bytes)
    }

    @Test
    fun `roster fields are read from the canonical encoding`() {
        assertEquals(hex32("rpd_hash"), roster.hash)
        assertEquals(hex("rpd"), roster.data)
        assertEquals(1, roster.version)
        assertEquals(1uL, roster.configSeq)
        assertEquals(1uL, roster.outerEpoch)
        assertNull(roster.previousHash)
        assertEquals(2, roster.outerThreshold)
        assertEquals(listOf(0u, 1u, 2u), roster.groups.map { it.groupId })
        roster.groups.forEach {
            assertEquals(2, it.threshold)
            assertEquals(1uL, it.shareEpoch)
            assertEquals(listOf(0u, 1u, 2u), it.roles.map { r -> r.id.adminId })
        }
        assertEquals(List(9) { id(it / 3, it % 3) }, roster.roleIds)
        roster.roles.forEachIndexed { i, role -> assertEquals(hostSecret(i).publicKey(), role.hostPublicKey) }
        assertEquals(roster.roles[4], roster.roleOf(hostSecret(4).publicKey()))
        assertNull(roster.role(id(3, 0)))
        assertEquals(roster, ConfederationRoster.fromData(hex("rpd")).right)
    }

    @Test
    fun `key state from the vectors`() {
        assertEquals(hex32("ksd_hash"), keyState.hash)
        assertEquals(hex("ksd"), keyState.data)
        assertEquals(XonlyPublicKey(PublicKey(hex("X"))), keyState.publicKey)
    }

    @Test
    fun `malformed descriptors are rejected`() {
        val rpd = hex("rpd")
        listOf(rpd.take(3), rpd.dropRight(1), rpd.concat(0), ByteVector(rpd.toByteArray().also { it[7] = 2 })).forEach {
            assertTrue(ConfederationRoster.fromData(it).isLeft)
        }
        val ksd = hex("ksd")
        listOf(ksd.dropRight(1), ksd.concat(0)).forEach { assertTrue(ConfederationKeyState.fromData(it, roster).isLeft) }
        // The key state of a roster is not the key state of another roster.
        val other = ConfederationRoster.fromData(withSharedEntity(rpd, 3, 0)).right!!
        assertTrue(ConfederationKeyState.fromData(ksd, other).isLeft)
    }

    @Test
    fun `access analysis accounts for entity overlap`() {
        assertEquals(ConfederationAccess(4, 4), roster.access().right)
        val overlap = withSharedEntity(roster.data, 3, 0)
        assertEquals(ConfederationAccess(3, 3), ConfederationRoster.fromData(overlap).right!!.access().right)
        val moreOverlap = withSharedEntity(overlap, 4, 1)
        assertEquals(ConfederationAccess(2, 2), ConfederationRoster.fromData(moreOverlap).right!!.access().right)
    }

    @Test
    fun `the largest roster is read in full and access analysis refuses it`() {
        // 64 groups of 2 admins, 2-of-2 inside, all 64 outside: 128 roles, the maximum.
        val out = ArrayList<Byte>()
        fun u32(v: Int) = (0..3).forEach { out += (v ushr (24 - 8 * it)).toByte() }
        fun u64(v: Long) = (0..7).forEach { out += (v ushr (56 - 8 * it)).toByte() }
        "CRPD".forEach { out += it.code.toByte() }
        u32(1); u64(1); u64(1); repeat(32) { out += 0 }; u32(64); u32(64); repeat(32) { out += 0 }
        repeat(64) { g ->
            u32(g); u64(1); u32(2); u32(2)
            repeat(2) { a ->
                u32(a)
                repeat(28) { out += 0 }; u32(2 * g + a + 1)
                PrivateKey(ByteArray(32).also { it[28] = 0; it[31] = (2 * g + a + 1).toByte(); it[30] = ((2 * g + a + 1) ushr 8).toByte() }).publicKey().value.toByteArray().forEach { out += it }
            }
        }
        val largest = ConfederationRoster.fromData(out.toByteArray().byteVector()).right!!
        assertEquals(10208, largest.data.size())
        assertEquals(64, largest.outerThreshold)
        assertEquals(128, largest.roles.size)
        assertEquals(id(63, 1), largest.roleIds.last())
        assertTrue(largest.access().isLeft)
    }

    @Test
    fun `dkg matches the vectors and every output is typed`() {
        val out = dkg()
        assertEquals(hex("dkg_fixed_ksd"), out.keyState.data)
        assertEquals(hex("dkg_fixed_transition"), out.genesis.data)
        assertEquals(hex32("dkg_fixed_transition_hash"), out.genesis.hash)
        assertEquals(hex("dkg_fixed_recovery"), out.recoveries.getValue(id(0, 0)).data)
        assertTrue(out.genesis.isGenesis)
        assertEquals(ConfederationOperation.Dkg, out.genesis.operation)
        assertEquals(roster.roleIds.toSet(), out.shares.keys)
        assertEquals(roster.roleIds.toSet(), out.recoveries.keys)
        out.shares.forEach { (role, share) ->
            assertEquals(role, share.role)
            assertTrue(share.isValidFor(out.keyState))
        }
        // The certificate round-trips through its canonical encoding against the states it connects.
        assertEquals(out.genesis, ConfederationTransition.fromData(out.genesis.data, null, out.keyState).right)
        // A share of one key state is not a share of another.
        assertFalse(out.shares.getValue(id(0, 0)).isValidFor(keyState))
    }

    @Test
    fun `per-role inputs are keyed by role and the caller's errors are raised`() {
        val seed = hex32("dkg_session_seed")
        assertFailsWith<IllegalArgumentException> { Confederation.dkgLocal(roster, seed, hostSecrets - id(2, 2), dealerSeeds, recoveryNonces) }
        assertFailsWith<IllegalArgumentException> { Confederation.dkgLocal(roster, seed, hostSecrets, dealerSeeds + (id(3, 0) to seed), recoveryNonces) }
        assertFailsWith<IllegalArgumentException> { Confederation.dkgLocal(roster, seed, hostSecrets, dealerSeeds, recoveryNonces - id(0, 0)) }
        // Host keys swapped between two roles.
        val swapped = hostSecrets + mapOf(id(0, 0) to hostSecrets.getValue(id(0, 1)), id(0, 1) to hostSecrets.getValue(id(0, 0)))
        assertFailsWith<IllegalArgumentException> { Confederation.dkgLocal(roster, seed, swapped, dealerSeeds, recoveryNonces) }

        val out = dkg()
        val message = session(0xb2)
        assertFailsWith<IllegalArgumentException> { Confederation.signLocal(out.keyState, out.shares - id(1, 2), hostSecrets, twoByTwo, emptyList(), session(0xb3), message) }
        val misplaced = out.shares + (id(0, 0) to out.shares.getValue(id(0, 1)))
        assertFailsWith<IllegalArgumentException> { Confederation.signLocal(out.keyState, misplaced, hostSecrets, twoByTwo, emptyList(), session(0xb3), message) }
    }

    @Test
    fun `signing verifies under the key state's key whatever the input order`() {
        val out = dkg()
        val message = session(0xb2)
        val sig = Confederation.signLocal(out.keyState, out.shares, hostSecrets, twoByTwo, emptyList(), session(0xb1), message).right!!
        assertTrue(Crypto.verifySignatureSchnorr(message, sig, out.keyState.publicKey))
        // Reversed maps and a selection listed backwards encode to the same native call.
        val reversed = Confederation.signLocal(
            out.keyState,
            out.shares.entries.reversed().associate { it.toPair() },
            hostSecrets.entries.reversed().associate { it.toPair() },
            ConfederationSignerSelection(linkedMapOf(1u to linkedSetOf(1u, 0u), 0u to linkedSetOf(1u, 0u))),
            emptyList(),
            session(0xb1),
            message,
        ).right!!
        assertEquals(sig, reversed)
        // Other authorized coalitions sign too.
        listOf(
            mapOf(0u to setOf(0u, 2u), 2u to setOf(1u, 2u)),
            mapOf(0u to setOf(0u, 1u, 2u), 1u to setOf(0u, 2u), 2u to setOf(0u, 1u)),
        ).forEachIndexed { i, groups ->
            val s = Confederation.signLocal(out.keyState, out.shares, hostSecrets, ConfederationSignerSelection(groups), emptyList(), session(0xc0 + i), message).right!!
            assertTrue(Crypto.verifySignatureSchnorr(message, s, out.keyState.publicKey))
        }
    }

    @Test
    fun `the tweaked signing vector verifies`() {
        val scalars = vectors["shares"]!!.jsonObject
        val shares = roster.roleIds.associateWith { role ->
            val scalar = PrivateKey.fromHex(scalars["(${role.groupId}, ${role.adminId})"]!!.jsonPrimitive.content)
            Confederation.wrapShare(role, scalar, keyState).right!!
        }
        val tweaks = listOf(ConfederationTweak(hex32("tweak"), isXonly = true))
        assertEquals(hex("signing_tweak_sequence"), ConfederationTweak.encode(tweaks).byteVector())
        val message = hex32("message")
        val selection = ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 2u)))
        val sig = Confederation.signLocal(keyState, shares, hostSecrets, selection, tweaks, hex32("signing_session_id"), message).right!!
        assertTrue(Crypto.verifySignatureSchnorr(message, sig, XonlyPublicKey(PublicKey(hex("tweaked_Q")))))
        assertFalse(Crypto.verifySignatureSchnorr(message, sig, keyState.publicKey))
    }

    @Test
    fun `signer selection is checked against the roster`() {
        val out = dkg()
        fun sign(groups: Map<UInt, Set<UInt>>) = Confederation.signLocal(out.keyState, out.shares, hostSecrets, ConfederationSignerSelection(groups), emptyList(), session(0xb4), session(0xb2))
        assertFailsWith<IllegalArgumentException> { sign(mapOf(0u to setOf(0u, 1u))) } // T = 2 groups
        assertFailsWith<IllegalArgumentException> { sign(mapOf(0u to setOf(0u, 1u), 3u to setOf(0u, 1u))) } // no group 3
        assertFailsWith<IllegalArgumentException> { sign(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u))) } // t_1 = 2
        assertFailsWith<IllegalArgumentException> { sign(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 3u))) } // no admin 3
        assertEquals(listOf(id(0, 0), id(0, 1), id(1, 0), id(1, 1)), ConfederationSignerSelection(mapOf(1u to setOf(1u, 0u), 0u to setOf(1u, 0u))).signers)
    }

    @Test
    fun `tweak sequences are encoded and checked`() {
        assertContentEquals(ByteArray(4), ConfederationTweak.encode(emptyList()))
        val zero = ConfederationTweak(ByteVector32.Zeroes, isXonly = false)
        assertEquals(4 + 64 * 33, ConfederationTweak.encode(List(ConfederationTweak.MAX_COUNT) { zero }).size)
        assertFailsWith<IllegalArgumentException> { ConfederationTweak.encode(List(ConfederationTweak.MAX_COUNT + 1) { zero }) }
        val aboveOrder = ConfederationTweak(ByteVector32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), isXonly = true)
        assertFailsWith<IllegalArgumentException> { ConfederationTweak.encode(listOf(aboveOrder)) }
    }

    @Test
    fun `transitions validate and conflict`() {
        val genesis = ConfederationTransition.fromData(hex("genesis_transition"), null, keyState).right!!
        assertEquals(hex32("transition_hash"), genesis.hash)
        assertEquals(ConfederationOperation.Dkg, genesis.operation)
        assertFalse(genesis.conflictsWith(genesis))
        // A genesis certificate has no predecessor, so it succeeds no accepted state.
        assertFalse(genesis.isSuccessorOf(keyState))
        val tampered = hex("genesis_transition").toByteArray().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertTrue(ConfederationTransition.fromData(tampered.byteVector(), null, keyState).isLeft)
        // Checked against the states it claims to connect.
        assertTrue(ConfederationTransition.fromData(hex("genesis_transition"), null, dkg().keyState).isLeft)

        val first = dkg()
        val second = dkg(ByteVector32(hex32("dkg_session_seed").toByteArray().also { it[31] = (it[31].toInt() xor 1).toByte() }))
        // The dealer seeds fix the key; the session seed changes the key state's operation session id, which is
        // enough for two different successors of the same (absent) predecessor.
        assertEquals(first.keyState.publicKey, second.keyState.publicKey)
        assertNotEquals(first.keyState, second.keyState)
        assertTrue(first.genesis.conflictsWith(second.genesis))
        assertFalse(first.genesis.conflictsWith(first.genesis))
    }

    @Test
    fun `recovery packages round-trip through their encoding`() {
        val share = Confederation.wrapShare(id(0, 0), PrivateKey.fromHex(vectors["shares"]!!.jsonObject["(0, 0)"]!!.jsonPrimitive.content), keyState).right!!
        val issued = Confederation.issueRecovery(share, hostSecret(0), keyState, ConfederationOperation.Dkg, hex32("transition_hash"), hex32("recovery_nonce")).right!!
        assertEquals(hex("recovery_package"), issued.data)
        assertEquals(269, issued.data.size())

        val parsed = ConfederationRecoveryPackage.fromData(issued.data, hostSecret(0)).right!!
        assertEquals(issued, parsed)
        val opened = parsed.open(hostSecret(0), keyState).right!!
        assertEquals(id(0, 0), opened.role)
        assertTrue(opened.isValidFor(keyState))

        assertTrue(ConfederationRecoveryPackage.fromData(issued.data, hostSecret(1)).isLeft)
        val tampered = issued.data.toByteArray().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertTrue(ConfederationRecoveryPackage.fromData(tampered.byteVector(), hostSecret(0)).isLeft)
        assertTrue(Confederation.issueRecovery(share, hostSecret(0), keyState, ConfederationOperation.Dkg, ByteVector32.Zeroes, hex32("recovery_nonce")).isLeft)
        assertTrue(Confederation.issueRecovery(share, hostSecret(1), keyState, ConfederationOperation.Dkg, hex32("transition_hash"), hex32("recovery_nonce")).isLeft)
        // A host key that is in no role of the roster.
        assertTrue(parsed.open(PrivateKey(ByteVector32.One), keyState).isLeft)
    }

    @Test
    fun `dkg recovery packages open to the dkg shares`() {
        val out = dkg()
        out.recoveries.forEach { (role, recovery) ->
            val host = hostSecrets.getValue(role)
            val opened = ConfederationRecoveryPackage.fromData(recovery.data, host).right!!.open(host, out.keyState).right!!
            assertEquals(role, opened.role)
            assertTrue(opened.isValidFor(out.keyState))
        }
        // A share recovered from a package cannot be opened under another key state.
        assertTrue(out.recoveries.getValue(id(0, 0)).open(hostSecret(0), keyState).isLeft)
    }

    @Test
    fun `shares rebind only with their own host key`() {
        val share = Confederation.wrapShare(id(0, 0), PrivateKey.fromHex(vectors["shares"]!!.jsonObject["(0, 0)"]!!.jsonPrimitive.content), keyState).right!!
        assertTrue(share.isValidFor(keyState))
        val rebound = share.rebind(hostSecret(0), keyState).right!!
        assertTrue(rebound.isValidFor(keyState))
        assertTrue(share.rebind(hostSecret(1), keyState).isLeft)
        // The wrong role, and a scalar that is not the role's.
        assertTrue(Confederation.wrapShare(id(0, 1), PrivateKey.fromHex(vectors["shares"]!!.jsonObject["(0, 0)"]!!.jsonPrimitive.content), keyState).isLeft)
        assertTrue(Confederation.wrapShare(id(0, 0), PrivateKey(ByteVector32.One), keyState).isLeft)
    }

    @Test
    fun `secrets stay out of toString`() {
        val scalar = vectors["shares"]!!.jsonObject["(0, 0)"]!!.jsonPrimitive.content
        val share = Confederation.wrapShare(id(0, 0), PrivateKey.fromHex(scalar), keyState).right!!
        assertEquals("ConfederationShare(role=(0, 0), <secret>)", share.toString())
        val out = dkg()
        val text = out.toString()
        assertTrue(text.contains("<secret>"))
        assertFalse(text.contains(scalar))
        assertFalse(text.contains(Hex.encode(out.shares.getValue(id(0, 0)).native)))
    }
}
