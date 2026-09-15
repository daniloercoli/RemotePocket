package com.aetnagroup.mydesk.network

import org.junit.Assert.*
import org.junit.Test

class PairingUrlTest {
    @Test fun releaseRequiresExplicitHttpsWithoutEmbeddedCredentials() {
        for (url in listOf("http://example.com", "example.com", ("https://" + "u:p@" + "example.com"), "https://example.com?token=x", "https://example.com#token", "file:///tmp/server", "")) {
            assertNull(url, validatedBackendUrl(url, false))
        }
        assertEquals("https://example.com", validatedBackendUrl(" https://example.com/ ", false))
    }
    @Test fun debugAllowsEmulatorHttpButNotInvalidSchemesOrSecrets() {
        assertEquals("http://10.0.2.2:8000", validatedBackendUrl("http://10.0.2.2:8000/", true))
        assertNull(validatedBackendUrl(("http://" + "owner:secret@" + "10.0.2.2:8000"), true))
        assertNull(validatedBackendUrl("javascript:alert(1)", true))
    }
}
