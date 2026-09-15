package com.aetnagroup.mydesk.accessibility

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Bitmap
import android.graphics.Path
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.aetnagroup.mydesk.AgentController
import com.aetnagroup.mydesk.network.CapturedFrame
import com.aetnagroup.mydesk.network.DeviceWebSocketClient
import com.aetnagroup.mydesk.storage.DeviceConfigStore
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

class MyDeskAccessibilityService : AccessibilityService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val screenshotExecutor = Executors.newSingleThreadExecutor()
    private var wsClient: DeviceWebSocketClient? = null
    private var activeSessionId: String? = null
    private var frameId = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        AgentController.attach(this)
    }

    fun applyConfiguration() {
        val store = DeviceConfigStore(this)
        if (store.paused || store.invalid || wsClient != null) return
        val config = store.load() ?: return
        AgentController.publish(AgentController.State.CONNECTING)
        wsClient = DeviceWebSocketClient(this, config).also { it.connect() }
    }

    fun stopControl(reason: String) {
        if (reason == "local_paused" || reason == "local_removed") {
            wsClient?.send(org.json.JSONObject().put("type", "device_local_stop").put("reason", reason))
        }
        activeSessionId?.let { wsClient?.send(org.json.JSONObject().put("type", "session_end").put("sessionId", it).put("reason", reason)) }
        endRemoteSession(reason)
        wsClient?.disconnect()
        wsClient = null
    }

    override fun onDestroy() {
        stopControl("service_destroyed")
        mainHandler.removeCallbacksAndMessages(null)
        AgentController.detach(this)
        screenshotExecutor.shutdownNow()
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() { stopControl("accessibility_interrupted"); AgentController.publish(AgentController.State.ACCESSIBILITY_DISABLED) }

    fun startRemoteSession(sessionId: String, client: DeviceWebSocketClient) {
        if (client !== wsClient || activeSessionId == sessionId) return
        AgentController.publish(AgentController.State.ACTIVE)
        activeSessionId = sessionId
        frameId = 0
        android.util.Log.i("AccessibilityService", "Starting remote session: $sessionId")
        captureLoop(client, sessionId)
    }

    fun endRemoteSession(reason: String) {
        android.util.Log.i("AccessibilityService", "Ending remote session: $reason")
        activeSessionId = null
        mainHandler.removeCallbacksAndMessages(null)
    }

    fun isCurrentSession(sessionId: String) = activeSessionId != null && activeSessionId == sessionId

    fun tap(x: Int, y: Int) {
        val path = Path().apply { moveTo(x.toFloat(), y.toFloat()) }
        dispatchGesture(
            GestureDescription.Builder()
                .addStroke(GestureDescription.StrokeDescription(path, 0, 80))
                .build(),
            null,
            null,
        )
    }

    fun swipe(fromX: Int, fromY: Int, toX: Int, toY: Int, durationMs: Long) {
        val path = Path().apply {
            moveTo(fromX.toFloat(), fromY.toFloat())
            lineTo(toX.toFloat(), toY.toFloat())
        }
        dispatchGesture(
            GestureDescription.Builder()
                .addStroke(GestureDescription.StrokeDescription(path, 0, durationMs))
                .build(),
            null,
            null,
        )
    }

    fun globalAction(action: String) {
        val globalAction = when (action.uppercase()) {
            "BACK" -> GLOBAL_ACTION_BACK
            "HOME" -> GLOBAL_ACTION_HOME
            "RECENTS" -> GLOBAL_ACTION_RECENTS
            "NOTIFICATIONS" -> GLOBAL_ACTION_NOTIFICATIONS
            else -> return
        }
        performGlobalAction(globalAction)
    }

    fun inputText(text: String) {
        // MVP: invio testo best-effort sul nodo attualmente focalizzato.
        val focused = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return
        val args = android.os.Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    private fun captureLoop(client: DeviceWebSocketClient, sessionId: String) {
        if (client !== wsClient || activeSessionId != sessionId || Build.VERSION.SDK_INT < 30) return
        val startTime = SystemClock.uptimeMillis()
        captureFrame { frame ->
            if (activeSessionId != sessionId) return@captureFrame
            if (frame != null) {
                client.sendScreenFrameBinary(sessionId, ++frameId, frame)
            }
            val elapsed = SystemClock.uptimeMillis() - startTime
            val delay = screenshotDelayMs(Build.VERSION.SDK_INT, elapsed, frame == null)
            mainHandler.postDelayed({ captureLoop(client, sessionId) }, delay)
        }
    }

    private fun captureFrame(onFrame: (CapturedFrame?) -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            android.util.Log.w("AccessibilityService", "Screenshot capture not supported on this Android version")
            onFrame(null)
            return
        }

        takeScreenshot(
            android.view.Display.DEFAULT_DISPLAY,
            screenshotExecutor,
            object : TakeScreenshotCallback {
                override fun onSuccess(screenshot: ScreenshotResult) {
                    val bitmap = Bitmap.wrapHardwareBuffer(
                        screenshot.hardwareBuffer,
                        screenshot.colorSpace,
                    )
                    screenshot.hardwareBuffer.close()

                    if (bitmap == null) {
                        mainHandler.post { onFrame(null) }
                        return
                    }

                    val width = bitmap.width
                    val height = bitmap.height
                    val softwareBitmap = bitmap.copy(Bitmap.Config.ARGB_8888, false)
                    bitmap.recycle()
                    if (softwareBitmap == null) {
                        mainHandler.post { onFrame(null) }
                        return
                    }
                    val output = ByteArrayOutputStream()
                    val quality = 60
                    val compressed = try {
                        softwareBitmap.compress(Bitmap.CompressFormat.JPEG, quality, output)
                    } finally {
                        softwareBitmap.recycle()
                    }
                    if (!compressed) {
                        mainHandler.post { onFrame(null) }
                        return
                    }
                    val jpegBytes = output.toByteArray()

                    android.util.Log.d("AccessibilityService", "Frame captured: ${width}x${height}")

                    mainHandler.post {
                        onFrame(
                            CapturedFrame(
                                width = width,
                                height = height,
                                quality = quality,
                                jpegBytes = jpegBytes,
                            )
                        )
                    }
                }

                override fun onFailure(errorCode: Int) {
                    if (errorCode == ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT) {
                        android.util.Log.w("AccessibilityService", "Screenshot throttled; retrying later")
                    } else {
                        android.util.Log.e("AccessibilityService", "Screenshot capture failed: $errorCode")
                    }
                    mainHandler.post { onFrame(null) }
                }
            },
        )
    }
}
