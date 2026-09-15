package com.aetnagroup.mydesk.network

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import com.aetnagroup.mydesk.AgentController
import com.aetnagroup.mydesk.storage.DeviceConfigStore
import com.aetnagroup.mydesk.accessibility.MyDeskAccessibilityService
import com.aetnagroup.mydesk.storage.DeviceConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject

class DeviceWebSocketClient(
    private val service: MyDeskAccessibilityService,
    private val config: DeviceConfig,
) {
    private val client = OkHttpClient.Builder().pingInterval(20, java.util.concurrent.TimeUnit.SECONDS).build()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var webSocket: WebSocket? = null
    private val connection = DeviceConnectionState(config.deviceId)
    private var shouldReconnect = true
    private var frameCount = 0L
    private var lastFrameTimeMs = 0L

    fun connect() {
        if (!shouldReconnect || webSocket != null) return
        mainHandler.removeCallbacksAndMessages(null)
        connection.beginConnection()
        val request = Request.Builder()
            .url(deviceWebSocketUrl(config.backendUrl, config.deviceId))
            .header("Authorization", "Bearer ${config.deviceToken}")
            .build()

        webSocket = client.newWebSocket(request, listener)
    }

    fun disconnect() {
        shouldReconnect = false
        mainHandler.removeCallbacksAndMessages(null)
        webSocket?.close(1000, "service_destroyed")
        webSocket = null
    }

    fun send(message: JSONObject) {
        webSocket?.send(message.toString())
    }

    fun sendScreenFrameBinary(sessionId: String, frameId: Long, frame: CapturedFrame) {
        val now = System.currentTimeMillis()
        val header = JSONObject()
            .put("type", "screen_frame")
            .put("sessionId", sessionId)
            .put("frameId", frameId)
            .put("timestamp", now)
            .put("width", frame.width)
            .put("height", frame.height)
            .put("format", "jpeg")
            .put("quality", frame.quality)
            .toString()

        val payload = encodeScreenFramePacket(header, frame.jpegBytes)
        if (webSocket?.send(payload) != true) return

        val frameTime = SystemClock.elapsedRealtime()
        if (lastFrameTimeMs == 0L) lastFrameTimeMs = frameTime
        frameCount++
        val elapsed = frameTime - lastFrameTimeMs
        if (elapsed >= 1_000L) {
            val fps = frameCount * 1000.0 / elapsed
            android.util.Log.d("Streaming", "Enqueued FPS: ${"%.1f".format(fps)}, frameId: $frameId")
            lastFrameTimeMs = frameTime
            frameCount = 0
        }
    }

    private val listener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            mainHandler.post {
                if (!current(webSocket)) return@post
                sendHello()
            }
        }
        override fun onMessage(webSocket: WebSocket, text: String) {
            mainHandler.post {
                if (!current(webSocket)) return@post
                try { handleMessage(webSocket, JSONObject(text)) } catch (_: Exception) { /* Ignore malformed peer messages. */ }
            }
        }
        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(code, reason)
            lost(webSocket, deviceCredentialsInvalid(closeCode = code))
        }
        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            lost(webSocket, deviceCredentialsInvalid(closeCode = code))
        }
        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            lost(webSocket, deviceCredentialsInvalid(httpCode = response?.code))
            response?.close()
        }
    }

    private fun current(socket: WebSocket) = shouldReconnect && webSocket === socket
    private fun lost(socket: WebSocket, invalid: Boolean) {
        mainHandler.post {
            if (!current(socket)) return@post
            webSocket = null
            service.endRemoteSession("connection_lost")
            mainHandler.removeCallbacksAndMessages(null)
            if (invalid) {
                shouldReconnect = false
                DeviceConfigStore(service).invalid = true
                AgentController.publish(AgentController.State.INVALID)
            } else scheduleReconnect()
        }
    }

    private fun heartbeat(socket: WebSocket) {
        if (!current(socket)) return
        send(JSONObject().put("type", "heartbeat"))
        mainHandler.postDelayed({ heartbeat(socket) }, 30_000L)
    }

    private fun sendHello() {
        send(
            JSONObject()
                .put("type", "device_hello")
                .put("deviceId", config.deviceId)
                .put("agentVersion", "0.1.0")
                .put("androidVersion", android.os.Build.VERSION.SDK_INT)
                .put(
                    "capabilities",
                    JSONObject()
                        .put("accessibilityGestures", true)
                        .put("accessibilityScreenshot", android.os.Build.VERSION.SDK_INT >= 30)
                        .put("globalActions", true)
                        .put("mediaProjection", false),
                )
        )
        android.util.Log.i("WebSocket", "Sent device_hello")
    }

    private fun handleMessage(socket: WebSocket, message: JSONObject) {
        val type = message.optString("type")
        if (type == "device_registered") {
            if (connection.confirmRegistration(message.optString("deviceId"))) {
                AgentController.publish(AgentController.State.ONLINE)
                heartbeat(socket)
            }
            return
        }
        if (!connection.registered) return
        if ((type.startsWith("input_") || type == "session_end") && !service.isCurrentSession(message.optString("sessionId"))) return
        android.util.Log.d("WebSocket", "Received: $type")
        when (type) {
            "session_start" -> {
                android.util.Log.i("WebSocket", "Starting remote session: ${message.optString("sessionId")}")
                service.startRemoteSession(message.getString("sessionId"), this)
            }
            "session_end" -> {
                android.util.Log.i("WebSocket", "Ending remote session: ${message.optString("reason")}")
                service.endRemoteSession(message.optString("reason", "backend_closed"))
                AgentController.publish(AgentController.State.ONLINE)
            }
            "input_tap" -> service.tap(message.getInt("x"), message.getInt("y"))
            "input_swipe" -> {
                val from = message.getJSONObject("from")
                val to = message.getJSONObject("to")
                service.swipe(
                    from.getInt("x"),
                    from.getInt("y"),
                    to.getInt("x"),
                    to.getInt("y"),
                    message.optLong("durationMs", 450L),
                )
            }
            "input_global_action" -> service.globalAction(message.getString("action"))
            "input_text" -> service.inputText(message.optString("text"))
        }
    }

    private fun scheduleReconnect() {
        if (!shouldReconnect) return
        webSocket = null
        val reconnectDelayMs = connection.nextRetryDelayMs()
        android.util.Log.i("WebSocket", "Scheduling reconnect in ${reconnectDelayMs}ms")
        AgentController.publish(AgentController.State.RECONNECTING)
        mainHandler.removeCallbacksAndMessages(null)
        mainHandler.postDelayed({ if (shouldReconnect) connect() }, reconnectDelayMs)
    }
}

data class CapturedFrame(
    val width: Int,
    val height: Int,
    val quality: Int,
    val jpegBytes: ByteArray,
)
