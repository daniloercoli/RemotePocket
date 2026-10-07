package com.aetnagroup.mydesk

import com.aetnagroup.mydesk.network.ConnectionPolicy
import org.junit.Assert.*
import org.junit.Test

class ManualConnectionPromptTest {
    @Test fun decliningIsRememberedUntilTheNextOpening() {
        val prompt = ManualConnectionPrompt()
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
        prompt.respond()
        repeat(3) {
            assertFalse(prompt.shouldShow(available = true, alreadyConnecting = false))
        }
        prompt.leaveApp()
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
    }

    @Test fun waitingForPairingOrAccessibilityDoesNotConsumeTheOffer() {
        val prompt = ManualConnectionPrompt()
        assertFalse(prompt.shouldShow(available = false, alreadyConnecting = false))
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
        // A configuration change retains the unanswered offer; backgrounding starts a new opening.
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
        prompt.respond()
        assertFalse(prompt.shouldShow(available = true, alreadyConnecting = false))
    }

    @Test fun incomingWakeDismissesTheOfferWithoutReopeningItWhenTheWindowExpires() {
        val prompt = ManualConnectionPrompt()
        val policy = ConnectionPolicy()
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
        assertTrue(policy.wake(0))
        assertFalse(prompt.shouldShow(available = false, alreadyConnecting = policy.shouldConnect(1)))
        assertFalse(policy.shouldConnect(ConnectionPolicy.INITIAL_WINDOW_MS))
        assertFalse(prompt.shouldShow(available = true, alreadyConnecting = false))
        prompt.leaveApp()
        assertTrue(prompt.shouldShow(available = true, alreadyConnecting = false))
    }

    @Test fun openingWithContinuousConnectionOrReconnectDoesNotOfferAnotherConnection() {
        val prompt = ManualConnectionPrompt()
        assertFalse(prompt.shouldShow(available = false, alreadyConnecting = true))
        // Switching off or losing a session must not open a dialog in the middle of app use.
        assertFalse(prompt.shouldShow(available = true, alreadyConnecting = false))
        prompt.leaveApp()
        assertFalse(prompt.shouldShow(available = false, alreadyConnecting = true))
    }
}
