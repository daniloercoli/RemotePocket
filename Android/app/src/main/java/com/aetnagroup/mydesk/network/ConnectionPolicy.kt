package com.aetnagroup.mydesk.network

/** Monotonic deadlines; temporary availability is deliberately never persisted. */
internal class ConnectionPolicy(var persistent: Boolean = false) {
    var active = false
        private set
    var deadline: Long? = null
        private set

    fun shouldConnect(now: Long) = persistent || active || (deadline?.let { now < it } == true)

    fun wake(now: Long): Boolean {
        if (shouldConnect(now)) return false
        deadline = now + INITIAL_WINDOW_MS
        return true
    }

    fun changeMode(value: Boolean) {
        if (value == persistent) return
        persistent = value
        deadline = null
    }

    fun sessionStarted() { active = true; deadline = null }

    fun sessionEnded(now: Long) {
        if (!active) return
        active = false
        deadline = if (persistent) null else now + GRACE_WINDOW_MS
    }

    fun reset() { active = false; deadline = null }

    companion object {
        const val INITIAL_WINDOW_MS = 600_000L
        const val GRACE_WINDOW_MS = 300_000L
    }
}
