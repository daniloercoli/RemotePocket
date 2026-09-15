package com.aetnagroup.mydesk.network

import java.net.URLEncoder
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

fun deviceWebSocketUrl(backendUrl: String, deviceId: String): String {
    val cleanBackend = backendUrl.trimEnd('/')
    val wsBase = when {
        cleanBackend.startsWith("https://") -> cleanBackend.replaceFirst("https://", "wss://")
        cleanBackend.startsWith("http://") -> cleanBackend.replaceFirst("http://", "ws://")
        else -> "ws://$cleanBackend"
    }
    val encodedDeviceId = URLEncoder.encode(deviceId, "UTF-8")
    return "$wsBase/device/ws?device_id=$encodedDeviceId"
}


/** Pairing URLs cannot embed credentials or silently fall back to cleartext. */
fun validatedBackendUrl(value: String, allowHttp: Boolean): String? {
    val url = value.trim().toHttpUrlOrNull() ?: return null
    if ((!url.isHttps && !allowHttp) || url.username.isNotEmpty() || url.password.isNotEmpty()
        || url.query != null || url.fragment != null) return null
    return url.toString().trimEnd('/')
}
