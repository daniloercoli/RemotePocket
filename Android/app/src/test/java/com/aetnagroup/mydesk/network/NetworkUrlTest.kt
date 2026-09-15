package com.aetnagroup.mydesk.network

import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkUrlTest {
    @Test
    fun convertsHttpBackendToWsDeviceEndpoint() {
        assertEquals(
            "ws://localhost:8000/device/ws?device_id=dev_123",
            deviceWebSocketUrl("http://localhost:8000/", "dev_123"),
        )
    }

    @Test
    fun convertsHttpsBackendToWssDeviceEndpoint() {
        assertEquals(
            "wss://example.com/device/ws?device_id=dev_123",
            deviceWebSocketUrl("https://example.com", "dev_123"),
        )
    }
}

