package com.aetnagroup.mydesk.network

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class ScreenFramePacketTest {
    @Test
    fun prefixesUtf8ByteLengthInLittleEndianAndPreservesJpegBytes() {
        // The accented character occupies two bytes; String.length would give 2.
        val jpeg = byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0, 0xff.toByte(), 0xd9.toByte())
        val packet = encodeScreenFramePacket("é!", jpeg)
        assertArrayEquals(
            byteArrayOf(3, 0, 0, 0, 0xc3.toByte(), 0xa9.toByte(), 0x21) + jpeg,
            packet.toByteArray(),
        )
    }
}
