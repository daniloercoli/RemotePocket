package com.aetnagroup.mydesk.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import com.aetnagroup.mydesk.network.WakeNonces

class DeviceConfigStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("mydesk_device_config", Context.MODE_PRIVATE)

    var corrupt = false
        private set
    var keepConnected: Boolean
        get() = prefs.getBoolean("keep_connected", false)
        set(value) { prefs.edit().putBoolean("keep_connected", value).commit() }
    val wakeKey: String?
        get() = try { prefs.getString("wake_key", null)?.let { decrypt(it) } } catch (_: Exception) { null }
    val configurationPending: Boolean
        get() = wakeKey == null || !prefs.contains("synced_keep_connected") ||
            prefs.getBoolean("synced_keep_connected", false) != keepConnected
    var lastWakeChannel: String?
        get() = prefs.getString("last_wake_channel", null)
        set(value) { prefs.edit().putString("last_wake_channel", value).commit() }

    fun saveWakeKey(key: String, persistent: Boolean) {
        check(prefs.edit().putString("wake_key", encrypt(key))
            .putBoolean("synced_keep_connected", persistent).commit())
    }

    /** Main-thread callers; commit before any connection so duplicates survive restarts. */
    fun consumeWakeNonce(nonce: String, expiresAt: Long, nowSeconds: Long): Boolean {
        val live = WakeNonces.consume(prefs.getStringSet("wake_nonces", emptySet()).orEmpty(), nonce, expiresAt, nowSeconds)
            ?: return false
        return prefs.edit().putStringSet("wake_nonces", live).commit()
    }
    var paused: Boolean
        get() = prefs.getBoolean("paused", false)
        set(value) { prefs.edit().putBoolean("paused", value).commit() }
    var invalid: Boolean
        get() = prefs.getBoolean("invalid", false)
        set(value) { prefs.edit().putBoolean("invalid", value).commit() }
    fun clear() { prefs.edit().clear().commit() }
    fun load(): DeviceConfig? {
        corrupt = false
        return try { loadConfig() } catch (_: Exception) { corrupt = true; null }
    }
    private fun loadConfig(): DeviceConfig? {
        val backendUrl = prefs.getString("backend_url", null) ?: return null
        val deviceId = prefs.getString("device_id", null) ?: return null
        val deviceName = prefs.getString("device_name", null) ?: return null
        val encryptedToken = prefs.getString("device_token", null) ?: return null

        return DeviceConfig(
            backendUrl = backendUrl,
            deviceId = deviceId,
            deviceToken = decrypt(encryptedToken),
            deviceName = deviceName,
        )
    }

    fun save(config: DeviceConfig) {
        prefs.edit()
            .remove("wake_key").remove("synced_keep_connected").remove("wake_nonces").remove("last_wake_channel")
            .putBoolean("invalid", false)
            .putString("backend_url", config.backendUrl)
            .putString("device_id", config.deviceId)
            .putString("device_name", config.deviceName)
            .putString("device_token", encrypt(config.deviceToken))
            .commit()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val payload = cipher.iv + encrypted
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    private fun decrypt(value: String): String {
        val payload = Base64.decode(value, Base64.NO_WRAP)
        val iv = payload.copyOfRange(0, 12)
        val encrypted = payload.copyOfRange(12, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.getKey(KEY_ALIAS, null)?.let { return it as SecretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()

        generator.init(spec)
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "mydesk_device_token"
    }
}
