package com.aetnagroup.mydesk.accessibility

import org.junit.Assert.assertEquals
import org.junit.Test

class ScreenshotTimingTest {
    @Test
    fun android11RequestsStayMoreThanOneSecondApart() {
        assertEquals(1_050L, 100L + screenshotDelayMs(30, 100L, false))
    }

    @Test
    fun android12AndLaterRequestsStayAbove333Milliseconds() {
        for (sdk in listOf(31, 32, 35)) {
            assertEquals(350L, 100L + screenshotDelayMs(sdk, 100L, false))
        }
    }

    @Test
    fun failuresWaitAFullRetryIntervalEvenAfterSlowCaptures() {
        assertEquals(1_050L, screenshotDelayMs(30, 2_000L, true))
        assertEquals(1_000L, screenshotDelayMs(35, 2_000L, true))
    }

    @Test
    fun slowCapturesNeverScheduleAnImmediateOrNegativeDelay() {
        assertEquals(10L, screenshotDelayMs(35, 500L, false))
    }
}
