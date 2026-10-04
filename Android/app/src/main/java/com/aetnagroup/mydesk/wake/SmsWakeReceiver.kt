package com.aetnagroup.mydesk.wake

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.aetnagroup.mydesk.AgentController

class SmsWakeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        if (parts.isEmpty() || parts.size > 10) return
        // All parts must belong to the same sender. No inbox/history access is needed.
        if (parts.map { it.originatingAddress }.distinct().size != 1) return
        val text = parts.joinToString("") { it.messageBody.orEmpty() }
        AgentController.receiveWake(context, text, "sms")
    }
}
