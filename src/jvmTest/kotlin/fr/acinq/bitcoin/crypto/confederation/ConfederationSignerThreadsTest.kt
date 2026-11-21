package fr.acinq.bitcoin.crypto.confederation

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.TestHelpers
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** A [ConfederationSigner] used from two threads at once confirms once: the other call is refused, never run. */
class ConfederationSignerThreadsTest {
    @Test
    fun `two threads confirming one signer get one confirmation`() {
        val vectors = TestHelpers.readResourceAsJson("confederation/vectors.json").jsonObject
        fun hex(name: String) = ByteVector(Hex.decode(vectors[name]!!.jsonPrimitive.content))
        val roster = ConfederationRoster.fromData(hex("rpd")).right!!
        val keyState = ConfederationKeyState.fromData(hex("ksd"), roster).right!!
        val scalars = vectors["shares"]!!.jsonObject
        val hostSecrets = roster.roleIds.withIndex().associate { (i, id) -> id to PrivateKey(ByteArray(32).also { it[30] = 0x10; it[31] = (i + 1).toByte() }) }
        val shares = roster.roleIds.associateWith { Confederation.wrapShare(it, PrivateKey.fromHex(scalars["(${it.groupId}, ${it.adminId})"]!!.jsonPrimitive.content), keyState).right!! }
        val selection = ConfederationSignerSelection(mapOf(0u to setOf(0u, 1u), 1u to setOf(0u, 1u)))
        val message = ByteVector32(ByteArray(32) { 0x7a })
        val pool = Executors.newFixedThreadPool(2)
        try {
            repeat(25) { attempt ->
                val session = ConfederationSigningSession.create(keyState, ByteVector32(ByteArray(32) { (attempt + 1).toByte() }), selection, emptyList()).right!!
                val signers = session.signers.mapIndexed { i, role ->
                    ConfederationSigning.generateNonce(session, role, shares.getValue(role), ByteVector32(ByteArray(32).also { it[0] = attempt.toByte(); it[31] = (i + 1).toByte() })).right!!
                }
                val transcript = ConfederationSigning.transcript(session, signers.associate { it.role to it.publicNonce }).right!!
                val target = signers[0]
                val start = CountDownLatch(1)
                val results = List(2) {
                    pool.submit<Either<Throwable, *>> {
                        start.await()
                        ConfederationSigning.confirm(target, transcript, message, hostSecrets.getValue(target.role))
                    }
                }
                start.countDown()
                val outcomes = results.map { it.get(30, TimeUnit.SECONDS) }
                assertEquals(1, outcomes.count { it.isRight }, "attempt $attempt: $outcomes")
                assertTrue(outcomes.single { it.isLeft }.left is IllegalStateException, "attempt $attempt: $outcomes")
                signers.forEach { it.abort() }
            }
        } finally {
            pool.shutdownNow()
        }
    }
}
