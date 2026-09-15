package com.aetnagroup.mydesk.network

/** Application registration, rather than an HTTP upgrade, confirms readiness. */
internal class DeviceConnectionState(private val deviceId: String) {
    var registered = false
        private set
    private var retryDelayMs = 1_000L

    fun beginConnection() {
        registered = false
    }

    fun confirmRegistration(registeredDeviceId: String): Boolean {
        if (registered || registeredDeviceId != deviceId) return false
        registered = true
        retryDelayMs = 1_000L
        return true
    }

    fun nextRetryDelayMs(): Long {
        registered = false
        val delay = retryDelayMs
        retryDelayMs = (retryDelayMs * 2).coerceAtMost(30_000L)
        return delay
    }
}
