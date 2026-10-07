package com.aetnagroup.mydesk

import android.content.ComponentName
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import com.aetnagroup.mydesk.accessibility.MyDeskAccessibilityService
import com.aetnagroup.mydesk.network.WakeCommand
import com.aetnagroup.mydesk.network.WakeProtocol
import com.aetnagroup.mydesk.storage.DeviceConfig
import com.aetnagroup.mydesk.storage.DeviceConfigStore
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Main-thread coordinator. Configuration requests happen only on setup or explicit changes. */
object AgentController {
    enum class State { UNPAIRED, ACCESSIBILITY_DISABLED, SETUP_REQUIRED, WAITING, CONNECTING, ONLINE, ACTIVE, RECONNECTING, PAUSED, INVALID }
    var state = State.UNPAIRED
        private set
    private val listeners = mutableSetOf<(State) -> Unit>()
    private var service: MyDeskAccessibilityService? = null
    private val main = Handler(Looper.getMainLooper())
    private val http = OkHttpClient.Builder().callTimeout(15, TimeUnit.SECONDS).build()
    private var configurationCall: Call? = null
    private var attemptedConfiguration: String? = null
    private data class PendingWake(val command: WakeCommand, val channel: String, val receivedAt: Long)
    private var pendingWake: PendingWake? = null

    fun observe(listener: (State) -> Unit) { listeners.add(listener); listener(state) }
    fun remove(listener: (State) -> Unit) { listeners.remove(listener) }
    fun publish(value: State) { state = value; listeners.toList().forEach { it(value) } }
    fun attach(value: MyDeskAccessibilityService) {
        service = value
        refresh(value)
        pendingWake?.let {
            pendingWake = null
            if (SystemClock.elapsedRealtime() - it.receivedAt < 600_000L) activate(value, it)
        }
    }
    fun detach(value: MyDeskAccessibilityService) {
        if (service === value) { service = null; publish(State.ACCESSIBILITY_DISABLED) }
    }

    fun refresh(context: Context) {
        val store = DeviceConfigStore(context)
        val config = store.load()
        when {
            store.corrupt || store.invalid -> { service?.stopControl("invalid_credentials"); publish(State.INVALID) }
            config == null -> { service?.stopControl("unpaired"); publish(State.UNPAIRED) }
            store.paused -> { service?.stopControl("local_paused"); publish(State.PAUSED) }
            else -> {
                if (store.configurationPending) configure(context.applicationContext, config, store.keepConnected)
                if (service == null) publish(State.ACCESSIBILITY_DISABLED) else {
                    service?.applyConfiguration()
                    publish(state) // Setup details can change without a socket state change.
                }
            }
        }
    }

    private fun cancelConfiguration() {
        configurationCall?.cancel()
        configurationCall = null
        attemptedConfiguration = null
    }

    fun retryConfiguration(context: Context) { cancelConfiguration(); refresh(context) }

    fun setKeepConnected(context: Context, value: Boolean) {
        DeviceConfigStore(context).keepConnected = value
        cancelConfiguration()
        refresh(context)
    }

    fun hasConnectionRequest(): Boolean = service?.connection?.hasConnectionRequest == true

    fun canConnectManually(): Boolean = (state == State.WAITING || state == State.SETUP_REQUIRED) &&
        service?.connection?.canConnectManually() == true

    fun connectManually() {
        if (!canConnectManually()) return
        val current = service ?: return
        if (current.connection.connectManually()) {
            DeviceConfigStore(current).lastWakeChannel = "app"
            publish(state)
        }
    }

    private fun configure(context: Context, config: DeviceConfig, persistent: Boolean) {
        val attempt = "${config.deviceId}:$persistent"
        if (configurationCall != null || attemptedConfiguration == attempt) return
        attemptedConfiguration = attempt
        val body = JSONObject().put("connection_mode", if (persistent) "persistent" else "on_demand")
            .toString().toRequestBody("application/json".toMediaType())
        val call = http.newCall(Request.Builder()
            .url("${config.backendUrl.trimEnd('/')}/api/devices/${config.deviceId}/agent-configuration")
            .header("Authorization", "Bearer ${config.deviceToken}").put(body).build())
        configurationCall = call
        fun complete(key: String?) {
            main.post {
                if (configurationCall !== call) return@post
                configurationCall = null
                val store = DeviceConfigStore(context)
                if (store.load() != config || store.keepConnected != persistent || store.paused) return@post
                if (key != null) {
                    try { store.saveWakeKey(key, persistent) } catch (_: Exception) { /* Explicit retry remains available. */ }
                }
                refresh(context)
            }
        }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { complete(null) }
            override fun onResponse(call: Call, response: Response) {
                val key = try {
                    response.use {
                        if (!it.isSuccessful) null else {
                            val json = JSONObject(it.body?.string().orEmpty())
                            val value = json.getString("wake_key")
                            if (json.optString("wake_protocol") == "RPW1" &&
                                value.matches(Regex("[A-Za-z0-9_-]{43}")) &&
                                java.util.Base64.getUrlDecoder().decode(value).size == 32) value else null
                        }
                    }
                } catch (_: Exception) { null }
                complete(key)
            }
        })
    }

    fun receiveWake(context: Context, text: String, channel: String) {
        if (channel != "sms" && channel != "telegram") return
        val store = DeviceConfigStore(context)
        val config = store.load() ?: return
        if (store.paused || store.invalid || store.corrupt) return
        val component = ComponentName(context, MyDeskAccessibilityService::class.java)
        val enabled = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            .orEmpty().split(':').any { ComponentName.unflattenFromString(it) == component }
        if (!enabled) return
        val now = System.currentTimeMillis() / 1000
        val command = WakeProtocol.verify(text, config.deviceId, store.wakeKey ?: return, now) ?: return
        if (!store.consumeWakeNonce(command.nonce, command.expiresAt, now)) return
        val pending = PendingWake(command, channel, SystemClock.elapsedRealtime())
        val current = service
        if (current != null) activate(current, pending)
        else if (pendingWake == null) {
            pendingWake = pending
            main.postDelayed({ if (pendingWake === pending) pendingWake = null }, 600_000L)
        }
    }

    private fun activate(current: MyDeskAccessibilityService, pending: PendingWake) {
        val store = DeviceConfigStore(current)
        if (store.paused || store.invalid || store.load() == null) return
        if (current.connection.wake(pending.command, pending.channel, pending.receivedAt)) {
            store.lastWakeChannel = pending.channel
            publish(state)
        }
    }

    fun pair(context: Context, config: DeviceConfig) {
        cancelConfiguration(); pendingWake = null
        service?.stopControl("new_pairing")
        DeviceConfigStore(context).save(config)
        refresh(context)
    }
    fun pause(context: Context) {
        cancelConfiguration(); pendingWake = null
        val store = DeviceConfigStore(context)
        store.paused = !store.paused
        if (store.paused) service?.stopControl("local_paused")
        refresh(context)
    }
    fun clear(context: Context) {
        cancelConfiguration(); pendingWake = null
        service?.stopControl("local_removed")
        DeviceConfigStore(context).clear()
        refresh(context)
    }
}
