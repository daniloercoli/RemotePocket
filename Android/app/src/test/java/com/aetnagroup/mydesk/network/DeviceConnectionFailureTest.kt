package com.aetnagroup.mydesk.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceConnectionFailureTest {
    @Test fun transientFailuresPreservePairing() {
        for (code in listOf(4409, 4429, 1000, 1001, 1006, 1011, 1012, 1013)) {
            assertFalse("WebSocket $code", deviceCredentialsInvalid(closeCode = code))
        }
        for (code in listOf(null, 409, 429, 500, 502, 503)) {
            assertFalse("HTTP $code", deviceCredentialsInvalid(httpCode = code))
        }
    }

    @Test fun authenticationDenialsInvalidatePairing() {
        for (code in listOf(4001, 4003, 4401, 4403, 1008)) {
            assertTrue("WebSocket $code", deviceCredentialsInvalid(closeCode = code))
        }
        for (code in listOf(401, 403)) {
            assertTrue("HTTP $code", deviceCredentialsInvalid(httpCode = code))
        }
    }
}
