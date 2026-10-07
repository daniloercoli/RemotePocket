# On-demand activation

The agent's **Mantieni connessione al server** option defaults to OFF on new and
upgraded installations. SMS and Telegram use the same authenticated command and
availability policy. No SMS provider, Telegram bot or FCM integration is required:
the owner copies the command from the console and sends it manually.

For interactive support, the user can instead open the paired Android app and
choose **Connetti** in **Connettersi al server?**. This opens the same temporary
WebSocket connection without SMS/Telegram permissions or wake-key provisioning.
The prompt is offered only with continuous mode OFF, accessibility ready, control
not paused and no connection already open or being attempted. It uses the saved
server URL; any VPN needed to reach it must already be connected. Session password
authentication is still required in the console. See the [app-opening workflow](../../Android/README.md#connect-by-opening-the-app).

## Everyday workflow: from an offline device to a session

Complete pairing, wake-key provisioning and the Android permissions once, while
the device has internet access. The [Android setup guide](../../Android/README.md#sms-and-telegram-activation)
lists the local settings. At least one reception channel must be ready; both can
be enabled together. With continuous connection OFF, the app then displays
**In attesa di connessione dall’app, SMS o Telegram**. An offline device in the console is normal at
this point: the agent is waiting locally and makes no periodic server requests.

1. Sign in to the console as the device owner. On the device card, choose
   **Attiva tramite SMS o Telegram**, even if it is offline.
2. The server checks ownership, revocation and generation limits, then creates a
   command for that device. The console displays the text and **Valido fino alle**.
   Generation alone does not contact or activate the phone.
3. Choose **Copia** and send the exact text yourself, using either channel below.
   The console does not store a destination phone number or Telegram contact and
   does not send messages. Keep those contact details in your normal address book.
4. The Android receiver passes the text to the shared verifier. It checks the
   signature, target device, expiry and previously consumed nonce locally. Invalid
   commands produce no server connection. A valid, unused command starts the
   temporary connection window and the agent connects to its already saved server.
5. After device authentication succeeds, the console updates its presence to
   online. The Android app shows the last activation channel; the server records
   the channel reported by the authenticated agent in activity history. A copied
   message, SMS delivery report or Telegram read receipt is not confirmation that
   the agent has connected.
6. Enter the device password and choose **Apri sessione**. Screen viewing and
   control use the existing server connection. Closing the session starts the
   five-minute grace period described below.

### Sending by SMS

Send the copied command as the entire body of an ordinary **SMS** to the SIM number
of the Android device being assisted. Do not add a greeting, quotation marks or a
signature. Use SMS explicitly if your messaging app normally chooses RCS or another
chat transport: those transports are not handled by the SMS receiver.

Android delivers the incoming SMS to the authorized agent, which joins multipart
segments before verification. The user does not need to open the message or tap a
link. No access to the old SMS inbox is needed. SMS reception uses the mobile
operator; the subsequent RemotePocket connection still needs Wi-Fi or mobile data.
If internet is temporarily unavailable after receipt, connection attempts use the
remaining ten-minute window. Normal operator SMS charges may apply.

### Sending by Telegram

Paste the same command as a plain-text message into a conversation with the
Telegram account used **on the target Android device**. A direct conversation is
the simplest setup to verify. No Telegram bot, API token or RemotePocket Telegram
account is needed.

Telegram must deliver a new notification on that device with the command text in
its notification data. With notification access granted, the agent extracts the
text from simple, expanded or conversation notifications and uses the same verifier
as SMS. It does not read Telegram chat history or log in to Telegram. The user does
not need to open Telegram or tap the notification.

The listener accepts the official Telegram Android packages and Telegram X.
There is no installation check. If Telegram is absent, notification access is not
granted, or Telegram publishes no notification containing the command, this channel
cannot activate the agent. In particular, verify message previews, grouped
notifications and delivery when the conversation is already open or another
Telegram client is in use. For a failed attempt, SMS is an alternative if configured.

Both channels are independent and can remain enabled. If the same command is sent
by both, the first valid reception consumes it; the second cannot open another
connection or extend a timer. Send a newly generated command for a later activation.

## Timing, presence and local control

There are two separate ten-minute clocks:

| Clock | Starts at | Meaning |
| --- | --- | --- |
| Command validity | Server generation | The device must receive and accept it before the displayed expiry. |
| Initial connection window | First valid receipt on Android, or local **Connetti** confirmation | The agent has up to ten minutes to connect and start a session, including network retries. |
| Session grace period | Session end or detected connection loss during a session | The agent remains available or retries for up to five minutes. A new session cancels this deadline. |

For example, a command generated at **14:00** expires at **14:10**. If accepted at
**14:03**, it opens a connection window until **14:13**. Without a session, the
agent closes the socket and stops retrying at 14:13. If a session starts at 14:05,
it can continue past both deadlines. If that session ends at **14:40**, the agent
returns to waiting at **14:45**, unless another session starts first. Command expiry
does not interrupt an already authorized session.

**Attivazione su richiesta** describes the device's last registered configuration;
**online/offline** describes its actual server connection. Offline can mean normal
local waiting, missing connectivity, pause or a stopped service. With no agent
connection, the server cannot distinguish those local conditions or guarantee
message delivery. A mode change that has not reached the server can also leave the
console showing the previous configuration until setup is retried successfully.

Turning **Mantieni connessione al server** ON makes the agent connect and reconnect
continuously, so no wake message is needed. Turning it OFF disconnects immediately
when no session is active, or preserves the active session and its five-minute
grace period. Local pause closes everything and ignores incoming wake messages.
Resuming restores waiting in OFF mode; confirm the app-opening prompt or send a
fresh command to activate it.
A reboot also returns OFF mode to waiting, without restoring a previous window.

Activation does not unlock the screen, enable a disabled service or bypass the
session password. Screen viewing/control still require the device to be unlocked
and the accessibility service to be enabled. SMS and Telegram carry only the wake
command; screenshots and control commands travel through RemotePocket.

### If activation does not work

| Symptom | What to check |
| --- | --- |
| Console activation button unavailable | Complete provisioning in the updated Android app; revoked devices cannot be activated. Existing old APKs only have continuous connection. |
| Android shows setup incomplete | Check server/network and `MYDESK_ENCRYPTION_KEY`, then use **Riprova configurazione attivazione**. Keep the existing pairing. |
| SMS arrives but the device stays offline | Verify the target SIM, actual SMS transport, complete unmodified text, SMS permission and enterprise installer allowlisting. |
| Telegram receives the chat message but the device stays offline | Check notification access and whether this Android device produced a notification containing the full command. A chat message alone is insufficient. |
| Both channels fail | Check command expiry/device clock, local pause, accessibility, network and battery restrictions. Reusing a consumed command does not reactivate the agent. |
| Device is online but no control is available | Open a session with the device password; check the screen is unlocked and accessibility is active. |

Receiving an SMS or notification does not by itself guarantee network access in
Doze. Configure the agent's battery exemption and verify the intended Android/OEM
setup with the hardware checklist below. See [Android's Doze restrictions](https://developer.android.com/training/monitoring-device-state/doze-standby).

## Configuration and rollout

1. Back up the existing database and keep `MYDESK_ENCRYPTION_KEY`. On a development
   installation without one, generate a Fernet key once:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
   Configure it in the server environment. Never rotate it without migrating
   existing encrypted data (MFA, outbox and wake keys).
2. Deploy the server/console first. Startup validates the complete schema before
   performing the known additive migration of `devices.connection_mode` and
   `devices.wake_key_encrypted`. The migration is idempotent on SQLite/PostgreSQL;
   other incomplete/incompatible schemas still fail without DDL. Legacy device
   records default to `persistent`; their existing APKs keep working unchanged.
3. Install the updated APK and open it. The local preference defaults to OFF when
   absent. Configuration retrieves the wake key with the existing device token;
   a new pairing is unnecessary. Permission setup is local and explicit.
4. Enable accessibility and SMS reception and/or Telegram notification access.
   Configure battery optimization according to the [Android guide](../../Android/README.md).
   When provisioning fails, the app keeps the pairing and exposes a retry button.
   Continuous mode can still connect even if wake-key provisioning is unavailable.

## Protocol and storage

Canonical wire text: `RPW1 <deviceId> <expiryUnixSeconds> <nonce> <mac>`.

- Exactly one ASCII space separates fields; only surrounding whitespace is ignored.
- Device IDs use the existing `dev_` plus 22 base64url characters.
- Expiry is a ten-digit UTC Unix timestamp, generated 600 seconds in the future.
- Nonce is 16 random bytes, unpadded base64url (22 characters).
- MAC is full HMAC-SHA-256 over the ASCII text preceding its final space, using a
  dedicated random 32-byte key; encode as unpadded base64url (43 characters).
- A command is 109 characters, within one GSM-7 SMS. Receivers still support
  multipart text. The shared public test vector is `protocol/wake-vectors.properties`.
- Verification checks signature, device and expiry locally before any connection.
  Up to 60 seconds of clock lag is tolerated in the maximum-future-expiry check;
  commands already expired according to the device clock are always rejected.
- Android commits consumed nonce/expiry entries before acting and retains them
  until expiry, capped at 128 live entries (fail closed when full). This deduplicates
  SMS/Telegram delivery and notification updates across process restarts.
- The server encrypts each key with its existing Fernet key. Android encrypts it
  with its Keystore-backed storage. Neither the command nor key is written to audit
  logs. Only the owner can generate a command; revocation disables generation and
  device authentication. Wake commands grant availability, never session access.

## API and console

| Interface | Authentication | Behavior |
| --- | --- | --- |
| `PUT /api/devices/{id}/agent-configuration` | Device bearer token for that ID | Body `{"connection_mode":"on_demand"}` or `persistent`; returns `connection_mode`, `wake_protocol: RPW1`, `wake_key`. Repeated setup preserves the key. |
| `POST /api/devices/{id}/wake-message` | Logged-in device owner | Returns `message` and `expires_at`. Ten requests/minute per owner, three/minute per device. |
| `device_list_request` with `watch: true` | Existing console WebSocket | Opts into `device_changed` events; older clients are not sent new unsolicited events. |
| `device_hello.wake` | Existing device WebSocket | Optional `{channel: sms\|telegram, nonce}`; audit records the channel reported by the authenticated agent. |

Key provisioning requires configured encryption (`503` otherwise). Wake generation
requires completed agent configuration (`409` otherwise); revoked/foreign devices
are not exposed. The APIs use `Cache-Control: no-store`.

The console action **Attiva tramite SMS o Telegram** works while the configured
device is offline. It displays the command, expiry and **Copia**; unsupported
clipboard access falls back to selecting the text. Device presence updates on an
authenticated connection, independently of the configured connection mode. The
existing password challenge is still required to open a remote session.

Configuration is attempted during first setup, initial upgrade and explicit mode
changes; manual retry is available. There is no polling to retrieve wake commands.

## Connection lifetime

In on-demand mode there is no socket, heartbeat, retry task or wake lock while
waiting. Reception or local confirmation opens a 10-minute budget (monotonic time), including connection
attempts. Starting a session removes the deadline. Ending or losing a session opens
a 5-minute grace budget; subsequent transport failures do not reset it. A new
session removes the grace deadline. Additional valid messages are consumed but do
not extend an existing connection window.

ON reconnects continuously. ON → OFF closes immediately when idle, otherwise waits
for the session and its 5-minute grace. Pause, configuration removal and invalid
credentials close immediately. Service/process restarts do not restore temporary
availability. Accessibility must remain enabled; activation does not unlock a
locked screen or recover a force-stopped app.

Temporary availability/active connections hold a partial wake lock with a bounded,
renewed timeout to execute deadline cleanup with the screen off. Doze network
access still requires the device's battery/background configuration. There is no
wake lock while dormant.

## Real-device acceptance checklist

Automated tests cover the shared signature vector, replay ledger, lifecycle policy,
API authorization, limits, schema upgrade and console interaction. These do not
substitute for the following hardware tests; record device/OEM, Android version,
APK installation method, SMS operator and Telegram version for each run.

- Check fresh installation and upgrade without losing pairing; OFF is the default.
- With OFF and an idle paired agent, open the app and decline the connection:
  no WebSocket is opened. Rotate the screen: no repeated offer. Leave and reopen,
  then confirm: one connection opens without SMS/Telegram permissions. Check the
  10-minute idle deadline and 5-minute post-session grace. Rotate with the dialog
  unanswered: it remains available. Existing connections, reconnects, continuous
  mode and local pause must suppress the offer. Send a valid SMS with the dialog
  open: it closes and only the SMS connection window is used.
- Grant SMS with the intended enterprise installer, and notification/accessibility
  permissions on a sideloaded APK, including restricted-settings requirements.
- For **each** channel: background the app, turn the screen off, force Doze, send a
  fresh signed command and confirm that the console reports online without a tap.
  Repeat while charging and unplugged, and after a device reboot.
- Check Telegram simple, extended and grouped notifications. Repeat with previews
  or notifications disabled: no command text means no activation. No installation
  probe or special missing-Telegram error is expected.
- Deliver the same command via both channels and then update its Telegram
  notification: one connection only. Repeat after restarting the app. Altered,
  wrong-device and expired messages must not create server requests.
- Observe 10 minutes without starting a session: socket and retries stop. Open and
  close a session: 5-minute grace; reopen during grace: no premature disconnect.
- Disable networking before the message and during a session. Restore within the
  budget, then after it: no retries or reconnection once the budget has expired.
- Toggle ON/OFF both idle and in a session; pause during reconnect and send a new
  command while paused. Pause must never be overridden.
- Observe server connections/requests and device traffic for at least 15 minutes in
  dormant OFF mode after provisioning: **zero agent requests**. Telegram's own
  traffic is outside this criterion.

Sources: [SMS permission](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_SMS),
[notification listener](https://developer.android.com/reference/android/service/notification/NotificationListenerService),
[Doze](https://developer.android.com/training/monitoring-device-state/doze-standby).
