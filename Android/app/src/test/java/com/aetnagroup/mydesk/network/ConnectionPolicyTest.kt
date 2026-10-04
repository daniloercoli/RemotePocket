package com.aetnagroup.mydesk.network

import org.junit.Assert.*
import org.junit.Test

class ConnectionPolicyTest {
    @Test fun defaultOffAndRestartAreDormant() {
        assertFalse(ConnectionPolicy().shouldConnect(0))
        val policy = ConnectionPolicy()
        policy.wake(0)
        assertFalse(ConnectionPolicy().shouldConnect(1))
    }
    @Test fun initialWindowNeverExtendedByDuplicatesOrLossWithoutSession() {
        val policy = ConnectionPolicy()
        assertTrue(policy.wake(0))
        assertFalse(policy.wake(10_000))
        policy.sessionEnded(20_000)
        assertEquals(600_000L, policy.deadline)
        assertTrue(policy.shouldConnect(599_999))
        assertFalse(policy.shouldConnect(600_000))
    }
    @Test fun activeSessionAndReopeningCancelIdleDeadline() {
        val policy = ConnectionPolicy()
        policy.wake(0)
        policy.sessionStarted()
        assertNull(policy.deadline)
        assertTrue(policy.shouldConnect(9_000_000))
        policy.sessionEnded(9_000_000)
        assertEquals(9_300_000L, policy.deadline)
        policy.sessionStarted()
        assertTrue(policy.shouldConnect(10_000_000))
        policy.sessionEnded(10_000_000)
        assertFalse(policy.shouldConnect(10_300_000))
    }
    @Test fun repeatedLossAfterSessionDoesNotRestartGrace() {
        val policy = ConnectionPolicy()
        policy.wake(0); policy.sessionStarted()
        policy.sessionEnded(10)
        policy.sessionEnded(1000)
        assertEquals(300_010L, policy.deadline)
    }
    @Test fun switchingModesAndPauseRespectActiveSession() {
        val policy = ConnectionPolicy()
        policy.changeMode(true)
        assertTrue(policy.shouldConnect(Long.MAX_VALUE))
        policy.changeMode(false)
        assertFalse(policy.shouldConnect(0))
        policy.changeMode(true); policy.sessionStarted(); policy.changeMode(false)
        assertTrue(policy.shouldConnect(1))
        policy.sessionEnded(2)
        assertEquals(300_002L, policy.deadline)
        policy.reset()
        assertFalse(policy.shouldConnect(3))
    }
}
