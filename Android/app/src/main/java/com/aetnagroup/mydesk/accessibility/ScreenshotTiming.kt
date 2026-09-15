package com.aetnagroup.mydesk.accessibility

internal fun screenshotDelayMs(sdkInt: Int, elapsedMs: Long, failed: Boolean): Long {
    // AOSP allows requests after 1000 ms on Android 11 and 333 ms on Android 12+.
    val intervalMs = if (sdkInt >= 31) 350L else 1_050L
    return if (failed) intervalMs.coerceAtLeast(1_000L) else (intervalMs - elapsedMs).coerceAtLeast(10L)
}
