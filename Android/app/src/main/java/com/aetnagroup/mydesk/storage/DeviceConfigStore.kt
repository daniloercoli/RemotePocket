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

class DeviceConfigStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("mydesk_device_config", Context.MODE_PRIVATE)

    var corrupt = false
        private set
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

