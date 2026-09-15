package com.aetnagroup.mydesk

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import com.aetnagroup.mydesk.storage.DeviceConfig
import com.aetnagroup.mydesk.storage.DeviceConfigStore
import okhttp3.*
import com.aetnagroup.mydesk.network.validatedBackendUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

class MainActivity : Activity() {
    private val httpClient = OkHttpClient.Builder().callTimeout(15, TimeUnit.SECONDS).build()
    private var pairingCall: Call? = null
    private lateinit var statusText: TextView
    private lateinit var pairButton: Button
    private lateinit var pauseButton: Button
    private lateinit var backendUrl: EditText
    private lateinit var deviceName: EditText
    private lateinit var pairingCode: EditText
    private lateinit var devicePassword: EditText
    private val listener: (AgentController.State) -> Unit = { renderState(it) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val config = DeviceConfigStore(this).load()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 32, 32, 32) }
        fun text(resource: Int) { root.addView(TextView(this).apply { setText(resource); textSize = 18f }) }
        fun input(resource: Int, value: String, secret: Boolean = false) = EditText(this).apply {
            setHint(resource); setText(value); setSingleLine(true)
            isSaveEnabled = !secret
            if (secret) inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            root.addView(this)
        }
        fun button(resource: Int, action: () -> Unit) = Button(this).apply { setText(resource); setOnClickListener { action() }; root.addView(this) }
        text(R.string.setup_title)
        backendUrl = input(R.string.backend_url, savedInstanceState?.getString("url") ?: config?.backendUrl ?: "https://")
        deviceName = input(R.string.device_name, savedInstanceState?.getString("name") ?: config?.deviceName ?: android.os.Build.MODEL)
        pairingCode = input(R.string.pairing_code, "", true)
        devicePassword = input(R.string.device_password, "", true)
        pairButton = button(R.string.pair_device) { pairDevice() }
        text(R.string.accessibility_guide)
        button(R.string.accessibility_settings) { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        if (android.os.Build.VERSION.SDK_INT < 30) text(R.string.screenshot_unavailable)
        text(R.string.operation_title)
        statusText = TextView(this).also { root.addView(it) }
        pauseButton = button(R.string.pause_control) { AgentController.pause(this) }
        button(R.string.remove_configuration) {
            AlertDialog.Builder(this).setMessage(R.string.remove_confirmation)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok) { _, _ -> AgentController.clear(this) }.show()
        }
        setContentView(ScrollView(this).apply { addView(root) })
    }
    override fun onStart() { super.onStart(); AgentController.observe(listener) }
    override fun onResume() { super.onResume(); AgentController.refresh(this) }
    override fun onStop() { AgentController.remove(listener); super.onStop() }
    override fun onDestroy() { pairingCall?.cancel(); pairingCall = null; super.onDestroy() }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("url", backendUrl.text.toString()); outState.putString("name", deviceName.text.toString())
        super.onSaveInstanceState(outState)
    }
    private fun renderState(state: AgentController.State) {
        val resource = when (state) {
            AgentController.State.UNPAIRED -> R.string.state_unpaired
            AgentController.State.ACCESSIBILITY_DISABLED -> R.string.state_accessibility
            AgentController.State.CONNECTING -> R.string.state_connecting
            AgentController.State.ONLINE -> R.string.state_online
            AgentController.State.ACTIVE -> R.string.state_active
            AgentController.State.RECONNECTING -> R.string.state_reconnecting
            AgentController.State.PAUSED -> R.string.state_paused
            AgentController.State.INVALID -> R.string.state_invalid
        }
        statusText.setText(resource)
        pauseButton.setText(if (DeviceConfigStore(this).paused) R.string.resume_control else R.string.pause_control)
        pauseButton.isEnabled = DeviceConfigStore(this).load() != null
    }
    private fun pairDevice() {
        if (pairingCall != null) return
        val url = validatedBackendUrl(backendUrl.text.toString(), BuildConfig.DEBUG)
        val name = deviceName.text.toString().trim()
        val code = pairingCode.text.toString().trim()
        val password = devicePassword.text.toString()
        if (url == null || name.isEmpty() || name.length > 200 || code.length != 8 || password.length < 8) {
            statusText.setText(R.string.invalid_fields); return
        }
        val base = url
        val body = JSONObject().put("pairing_code", code).put("name", name).put("device_password", password)
            .toString().toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url("$base/api/devices/pair").post(body).build()
        pairButton.isEnabled = false; statusText.setText(R.string.pairing_progress)
        val call = httpClient.newCall(request)
        pairingCall = call
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { complete(call, null) }
            override fun onResponse(call: Call, response: Response) {
                val config = try {
                    response.use {
                        if (!it.isSuccessful) null else {
                            val json = JSONObject(it.body?.string().orEmpty())
                            DeviceConfig(base, json.getString("device_id"), json.getString("device_token"), json.getString("device_name"))
                        }
                    }
                } catch (_: Exception) { null }
                complete(call, config)
            }
        })
    }
    private fun complete(call: Call, config: DeviceConfig?) {
        runOnUiThread {
            if (isDestroyed || pairingCall !== call) return@runOnUiThread
            pairingCall = null; pairButton.isEnabled = true
            pairingCode.text.clear(); devicePassword.text.clear()
            if (config == null) { statusText.setText(R.string.pairing_failed); return@runOnUiThread }
            try { AgentController.pair(this, config) } catch (_: Exception) { statusText.setText(R.string.state_invalid) }
        }
    }
}
