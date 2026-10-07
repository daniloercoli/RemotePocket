package com.aetnagroup.mydesk.network

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import com.aetnagroup.mydesk.AgentController
import com.aetnagroup.mydesk.accessibility.MyDeskAccessibilityService
import com.aetnagroup.mydesk.storage.DeviceConfigStore

/** Owns availability, reconnect scheduling and deadlines independently of socket heartbeats. */
class AgentConnectionManager(private val service: MyDeskAccessibilityService) {
    private val policy = ConnectionPolicy(DeviceConfigStore(service).keepConnected)
    private val timer = Handler(Looper.getMainLooper())
    private val retry = Handler(Looper.getMainLooper())
    private var stopping = false
    var client: DeviceWebSocketClient? = null
        private set
    private var receipt: Pair<String, String>? = null
    private val wakeLock = (service.getSystemService(Context.POWER_SERVICE) as PowerManager)
        .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "RemotePocket:connection").apply { setReferenceCounted(false) }

    fun refresh() {
        val store = DeviceConfigStore(service)
        policy.changeMode(store.keepConnected)
        val config = store.load()
        if (config == null || store.paused || store.invalid) { stop("unavailable"); return }
        if (!policy.shouldConnect(SystemClock.elapsedRealtime())) {
            stop("idle_timeout")
            AgentController.publish(if (store.configurationPending) AgentController.State.SETUP_REQUIRED else AgentController.State.WAITING)
            return
        }
        if (client == null) {
            client = DeviceWebSocketClient(service, config, receipt)
            AgentController.publish(AgentController.State.CONNECTING)
            client?.connect()
        }
        scheduleDeadline()
    }

    fun wake(command: WakeCommand, channel: String, receivedAt: Long): Boolean {
        if (SystemClock.elapsedRealtime() - receivedAt >= ConnectionPolicy.INITIAL_WINDOW_MS) return false
        if (!policy.wake(receivedAt)) return false
        receipt = channel to command.nonce
        refresh()
        return true
    }

    val hasConnectionRequest: Boolean
        get() = client != null || policy.shouldConnect(SystemClock.elapsedRealtime())

    fun canConnectManually(): Boolean {
        val store = DeviceConfigStore(service)
        return !store.keepConnected && !store.paused && !store.invalid &&
            store.load() != null && !hasConnectionRequest
    }

    fun connectManually(): Boolean {
        // Recheck after consent: an SMS, a mode change or pause may have intervened.
        if (!canConnectManually() || !policy.wake(SystemClock.elapsedRealtime())) return false
        receipt = null // Local consent is not a signed SMS/Telegram wake receipt.
        refresh()
        return true
    }

    fun isAllowed(): Boolean {
        val store = DeviceConfigStore(service)
        return !store.paused && !store.invalid && policy.shouldConnect(SystemClock.elapsedRealtime())
    }

    fun registered() { AgentController.publish(AgentController.State.ONLINE) }

    fun sessionStarted() { policy.sessionStarted(); scheduleDeadline() }

    fun sessionEnded() {
        policy.sessionEnded(SystemClock.elapsedRealtime())
        scheduleDeadline()
    }

    fun transportLost(invalid: Boolean, delayMs: Long) {
        service.endRemoteSession("connection_lost")
        if (invalid) {
            DeviceConfigStore(service).invalid = true
            stop("invalid_credentials")
            AgentController.publish(AgentController.State.INVALID)
            return
        }
        if (!isAllowed()) { refresh(); return }
        AgentController.publish(AgentController.State.RECONNECTING)
        retry.removeCallbacksAndMessages(null)
        retry.postDelayed({
            if (isAllowed()) client?.connect() else refresh()
        }, delayMs)
        scheduleDeadline()
    }

    private fun scheduleDeadline() {
        if (stopping) return
        timer.removeCallbacksAndMessages(null)
        val now = SystemClock.elapsedRealtime()
        // No lock or timer while dormant. A bounded lock keeps temporary deadlines honest
        // with the screen off; it is renewed only during an actual connection/session.
        if (policy.shouldConnect(now)) {
            wakeLock.acquire(11 * 60_000L)
            val remaining = policy.deadline?.let { (it - now).coerceAtLeast(0) }
            timer.postDelayed({
                if (!policy.shouldConnect(SystemClock.elapsedRealtime())) refresh() else scheduleDeadline()
            }, remaining?.coerceAtMost(5 * 60_000L) ?: (5 * 60_000L))
        } else if (wakeLock.isHeld) wakeLock.release()
    }

    fun stop(reason: String) {
        stopping = true
        policy.reset()
        timer.removeCallbacksAndMessages(null)
        retry.removeCallbacksAndMessages(null)
        service.endRemoteSession(reason)
        client?.disconnect()
        client = null
        receipt = null
        if (wakeLock.isHeld) wakeLock.release()
        stopping = false
    }
}
