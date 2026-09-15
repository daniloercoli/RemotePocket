package com.aetnagroup.mydesk.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceConnectionStateTest {
    @Test fun duplicateHandshakesIncreaseBackoffWithoutConfirmingOnline() {
        val connection = DeviceConnectionState("device")
        for (delay in listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L)) {
            connection.beginConnection()
            // HTTP upgrade succeeds, then the server closes with 4409 without
            // sending device_registered. Only that message can mark us ready.
            assertFalse(connection.registered)
            assertFalse(deviceCredentialsInvalid(closeCode = 4409))
            assertEquals(delay, connection.nextRetryDelayMs())
        }
    }

    @Test fun onlyRegistrationForThisDeviceResetsBackoff() {
        val connection = DeviceConnectionState("device")
        assertEquals(1_000L, connection.nextRetryDelayMs())
        connection.beginConnection()
        assertFalse(connection.confirmRegistration("other-device"))
        assertFalse(connection.registered)
        assertEquals(2_000L, connection.nextRetryDelayMs())
        connection.beginConnection()
        assertTrue(connection.confirmRegistration("device"))
        assertTrue(connection.registered)
        assertEquals(1_000L, connection.nextRetryDelayMs())
        assertFalse(connection.registered)
    }

    @Test fun repeatedRegistrationCannotPublishOnlineAgainDuringAnActiveSession() {
        val connection = DeviceConnectionState("device")
        connection.beginConnection()
        assertTrue(connection.confirmRegistration("device"))
        // The server also acknowledges device_hello with device_registered.
        assertFalse(connection.confirmRegistration("device"))
        connection.beginConnection()
        assertFalse(connection.registered)
        assertTrue(connection.confirmRegistration("device"))
    }
}
