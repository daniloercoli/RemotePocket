package com.aetnagroup.mydesk.network

import org.junit.Assert.*
import org.junit.Test
import java.util.Properties

class WakeProtocolTest {
    private val vector = Properties().apply {
        WakeProtocolTest::class.java.getResourceAsStream("/wake-vectors.properties")!!.use { load(it) }
    }
    private val message = vector.getProperty("message")
    private val device = vector.getProperty("device_id")
    private val key = vector.getProperty("key")
    private val now = vector.getProperty("now").toLong()

    @Test fun sharedPythonVectorFitsOneSms() {
        val result = WakeProtocol.verify(message, device, key, now)!!
        assertEquals(vector.getProperty("nonce"), result.nonce)
        assertEquals(now + 600, result.expiresAt)
        assertTrue(message.length <= 160)
        assertTrue(message.all { it.code < 128 })
    }

    @Test fun rejectsAlterationWrongDeviceExpiryAndWrongKey() {
        assertNull(WakeProtocol.verify(message.replace("RPW1", "RPW2"), device, key, now))
        assertNull(WakeProtocol.verify(message.replace((now+600).toString(), (now+599).toString()), device, key, now))
        assertNull(WakeProtocol.verify(message, "dev_BBBBBBBBBBBBBBBBBBBBBB", key, now))
        assertNull(WakeProtocol.verify(message, device, key, now+600))
        assertNotNull(WakeProtocol.verify(message, device, key, now-1))
        assertNull(WakeProtocol.verify(message, device, key, now-61))
        assertNull(WakeProtocol.verify(message, device, "A".repeat(43), now))
        assertNull(WakeProtocol.verify("$message extra", device, key, now))
    }

    @Test fun extractsTelegramTextWithoutTrustingSender() {
        assertEquals(listOf(message), WakeProtocol.candidates("Tecnico: $message"))
        assertTrue(WakeProtocol.candidates("RPW1 connect").isEmpty())
        assertTrue(WakeProtocol.candidates("a".repeat(20000)).isEmpty())
    }

    @Test fun nonceDeduplicatesChannelsAndSurvivesReload() {
        val accepted = WakeProtocol.verify(message, device, key, now)!!
        val persisted = WakeNonces.consume(emptySet(), accepted.nonce, accepted.expiresAt, now)!!
        // Simulate a new store/process reading persisted entries after SMS acceptance.
        assertNull(WakeNonces.consume(persisted.toSet(), accepted.nonce, accepted.expiresAt, now+1))
        val next = WakeNonces.consume(persisted, "new-nonce", now+1200, now+601)!!
        assertEquals(setOf("new-nonce:${now+1200}"), next)
    }
}
