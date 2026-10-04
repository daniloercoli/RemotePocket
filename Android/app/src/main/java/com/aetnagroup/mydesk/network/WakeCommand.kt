package com.aetnagroup.mydesk.network

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class WakeCommand(val nonce: String, val expiresAt: Long)

object WakeProtocol {
    private val pattern = Regex("RPW1 (dev_[A-Za-z0-9_-]{22}) ([0-9]{10}) ([A-Za-z0-9_-]{22}) ([A-Za-z0-9_-]{43})")

    fun verify(text: String, deviceId: String, key: String, nowSeconds: Long): WakeCommand? {
        if (text.length > 160) return null
        val match = pattern.matchEntire(text.trim()) ?: return null
        val expiry = match.groupValues[2].toLongOrNull() ?: return null
        // Allow one minute of clock lag, but never accept an expired command.
        if (match.groupValues[1] != deviceId || expiry <= nowSeconds || expiry > nowSeconds + 660L) return null
        return try {
            val bytes = Base64.getUrlDecoder().decode(key)
            if (bytes.size != 32) return null
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(bytes, "HmacSHA256"))
            val signed = match.value.substringBeforeLast(' ').toByteArray(Charsets.US_ASCII)
            val signature = Base64.getUrlDecoder().decode(match.groupValues[4])
            // Require canonical encoding, including its otherwise-unused trailing bits.
            val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(signed))
            if (signature.size != 32 || !MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), match.groupValues[4].toByteArray(Charsets.US_ASCII))) null
            else WakeCommand(match.groupValues[3], expiry)
        } catch (_: IllegalArgumentException) { null }
    }

    /** Notification wrappers may add sender labels. Only complete signed commands qualify. */
    fun candidates(text: CharSequence?): List<String> {
        if (text == null || text.length > 16_384) return emptyList()
        return pattern.findAll(text).take(20).map { it.value }.toList()
    }
}
