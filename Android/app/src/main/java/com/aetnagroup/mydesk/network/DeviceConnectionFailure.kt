package com.aetnagroup.mydesk.network

// Authenticated duplicates are accepted then closed with 4409 by the server.
// They must reconnect with the same credentials; only authentication denials
// invalidate the persisted pairing.
internal fun deviceCredentialsInvalid(closeCode: Int? = null, httpCode: Int? = null): Boolean =
    closeCode in setOf(4001, 4003, 4401, 4403, 1008) || httpCode in setOf(401, 403)
