package com.aetnagroup.mydesk.network

import okio.Buffer
import okio.ByteString

internal fun encodeScreenFramePacket(header: String, jpegBytes: ByteArray): ByteString {
    val headerBytes = header.toByteArray(Charsets.UTF_8)
    return Buffer()
        .writeIntLe(headerBytes.size)
        .write(headerBytes)
        .write(jpegBytes)
        .readByteString()
}
