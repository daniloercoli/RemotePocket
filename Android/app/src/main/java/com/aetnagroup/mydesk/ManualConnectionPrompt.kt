package com.aetnagroup.mydesk

/** One offer per app opening; retained during configuration changes. */
internal class ManualConnectionPrompt {
    private var handled = false

    fun shouldShow(available: Boolean, alreadyConnecting: Boolean): Boolean {
        if (alreadyConnecting) handled = true
        return available && !handled
    }

    fun respond() { handled = true }
    fun leaveApp() { handled = false }
}
