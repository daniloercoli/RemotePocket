package com.aetnagroup.mydesk.wake

import android.app.Notification
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.aetnagroup.mydesk.AgentController
import com.aetnagroup.mydesk.network.WakeProtocol

class TelegramWakeListener : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        // Package filtering is not an installation check. The MAC authenticates the command.
        if (sbn.packageName !in PACKAGES) return
        val extras = sbn.notification.extras ?: return
        val texts = mutableListOf<CharSequence?>()
        texts.add(extras.getCharSequence(Notification.EXTRA_TEXT))
        texts.add(extras.getCharSequence(Notification.EXTRA_BIG_TEXT))
        extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.let { texts.addAll(it) }
        extras.getParcelableArray(Notification.EXTRA_MESSAGES)?.let { bundles ->
            if (Build.VERSION.SDK_INT >= 30) {
                Notification.MessagingStyle.Message.getMessagesFromBundleArray(bundles)
                    .forEach { texts.add(it.text) }
            } else {
                // MessagingStyle's text bundle field predates the public API-30 parser.
                bundles.filterIsInstance<Bundle>().forEach { texts.add(it.getCharSequence("text")) }
            }
        }
        // Persistent nonce consumption also deduplicates grouped/updated notifications
        // and commands delivered over both channels. Never replay active notifications.
        texts.flatMap { WakeProtocol.candidates(it) }.distinct().forEach {
            AgentController.receiveWake(this, it, "telegram")
        }
    }

    companion object {
        val PACKAGES = setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram")
    }
}
