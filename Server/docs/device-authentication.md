# Device session authentication

The console authenticates a device session using the proof construction from
[SCRAM-SHA-256 (RFC 7677)](https://www.rfc-editor.org/rfc/rfc7677) and
[RFC 5802 section 3](https://www.rfc-editor.org/rfc/rfc5802#section-3).
This is an application protocol carried in JSON WebSocket messages, not a SASL
implementation. Passwords use their literal UTF-8 bytes without SASLprep or
Unicode normalization, matching device pairing.

## Pairing and storage

The Android pairing request supplies `device_password` over HTTPS. The server
derives a 32-byte salted password with PBKDF2-HMAC-SHA-256, a random 16-byte salt
and 600,000 iterations. It persists the salt, iteration count, StoredKey and
ServerKey. The password, SaltedPassword and ClientKey are not persisted.
Account password hashing remains Argon2.

## Session opening

1. On an authenticated console connection, send `session_challenge_request` with
   `deviceId` and `clientNonce` (32 random bytes encoded as 64 lowercase hex digits).
2. The server checks device ownership, revocation and online status. It returns
   `session_challenge` with `deviceId`, `challengeId`, `clientNonce`, `nonce`,
   `salt` (base64), `iterations` and `expiresIn` (60 seconds). The server nonce
   appends 32 fresh random bytes, encoded as hex, to the client nonce.
3. The client derives ClientKey and StoredKey. The transcript is the SCRAM
   AuthMessage, with the escaped device ID as the username:
   `n=<deviceId>,r=<clientNonce>,r=<nonce>,s=<salt>,i=<iterations>,c=biws,r=<nonce>`.
   ClientProof is ClientKey XOR HMAC(StoredKey, AuthMessage).
4. Send `session_start_request` with `deviceId`, `challengeId` and `proof`
   (base64 ClientProof). Password-bearing messages are rejected.
5. The server consumes the pending challenge before checking the proof and
   rechecks authentication, device access and session quotas. A failed proof
   also consumes the challenge. Successful `session_started` messages include
   `serverProof`, the base64 HMAC(ServerKey, AuthMessage); the console verifies
   this before accepting the session.

Each console connection has its own bounded challenge store. One pending
challenge is allowed per device; requesting another replaces it. At most
`MYDESK_MAX_REMOTE_SESSIONS` challenges are pending on a connection. Disconnect
discards all pending challenges. Challenge requests and proof submissions each
have a separate five-per-minute owner budget, in addition to the shared control
message limit. A proof cannot be used on another connection or device, or reused
to open another session.

The console requires Web Crypto, available over HTTPS or on localhost. It clears
the password input immediately, imports the password into a non-exportable
CryptoKey, wipes temporary byte buffers and discards pending state after success,
failure, timeout, logout or reconnect. It does not persist device passwords,
derived keys or proofs in browser storage.

## Security scope

HTTPS/WSS is still necessary: challenge-response does not replace transport
authentication or prevent an active attacker from relaying an exchange. Captured
exchanges or stolen verifiers can support offline password guessing, so device
password strength still matters. A compromised endpoint or process memory dump
can expose live cryptographic material; managed runtimes cannot guarantee its
complete erasure. The password is still processed during initial HTTPS pairing,
but it is absent from WebSocket session-opening messages.

Tests cover the RFC 7677 vector in Python and browser Web Crypto, successful
proofs, wrong and replayed proofs, expiry, connection binding, access revocation,
bounded pending state and stale browser operations.
