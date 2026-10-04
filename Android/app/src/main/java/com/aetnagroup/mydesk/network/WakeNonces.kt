package com.aetnagroup.mydesk.network

/** Persist the returned set atomically before acting; null means replay or capacity exhausted. */
object WakeNonces {
    fun consume(entries: Set<String>, nonce: String, expiresAt: Long, now: Long): Set<String>? {
        val live = entries.filter { (it.substringAfter(':', "").toLongOrNull() ?: 0) > now }.toMutableSet()
        if (live.any { it.substringBefore(':') == nonce } || live.size >= 128) return null
        live.add("$nonce:$expiresAt")
        return live
    }
}
