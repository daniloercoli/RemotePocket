# RemotePocket Android app

The Android app connects a device to the RemotePocket server. It uses an accessibility service to capture the screen and handle remote input.

## Requirements

- Android Studio, JDK 17 and Android SDK Platform 35.
- An Android device or emulator. Screen capture requires Android 11 / API 30 or newer. The minimum install version is Android 8 / API 26.
- A running [RemotePocket server](../Server/README.md).

The project includes the Gradle Wrapper, so a separate Gradle installation is not required.

## Run from Android Studio

1. Open this `Android` folder as a project.
2. Set the Gradle JDK to 17 in Android Studio settings.
3. Install Android SDK Platform 35 through the SDK Manager and let Gradle sync finish.
4. Connect a device with USB debugging enabled and accept its authorization prompt, or start an emulator.
5. Select the `app` run configuration and click **Run**.

Android Studio builds, installs and opens the debug app.

## Build from a terminal

Run these commands from the `Android` folder. Set `JAVA_HOME` to your JDK 17 installation. Set `ANDROID_HOME` to your Android SDK directory, or let Android Studio create `local.properties` with the SDK path. That file is ignored by Git because the path is specific to your computer.

On macOS or Linux:

```bash
./gradlew :app:assembleDebug
```

On Windows, in PowerShell:

```powershell
.\gradlew.bat :app:assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

To install it on a connected device or running emulator:

```bash
./gradlew :app:installDebug
```

On Windows, use `.\gradlew.bat :app:installDebug`. Open **RemotePocket Agent** from the device's app list after installation.

## Pair with the server

1. Open the web console on your computer and log in. On a new server, create the first owner account first.
2. Create a pairing code in the console. It has 8 characters, works once and expires after 10 minutes by default.
3. In RemotePocket Agent, enter the server URL, a device name, the code and a device password of at least 8 characters.
4. Tap the pairing button.
5. Open accessibility settings from the app and enable **RemotePocket Remote Control**.
6. Confirm **Connetti** when the app offers to connect, or configure SMS/Telegram activation below. Once the device is online in the console, enter its device password and open a session.

The device password is separate from the account password. The app does not save the pairing code or device password. It saves the server URL, device ID and name, and stores the device token and dedicated wake key encrypted with Android Keystore.

## Connect by opening the app

With **Mantieni connessione al server** OFF, opening or returning to the app offers
**Connettersi al server?** when the paired device is idle and accessibility is ready.
Choose **Connetti** to make it available for interactive support, or **Non ora** to
keep waiting locally. The dialog shows the saved server URL. If that address
requires a VPN, connect the VPN separately before starting support.

This option needs no SMS/Telegram permissions or wake key. It opens the existing
authenticated WebSocket for up to 10 minutes, keeps it open during a session, then
allows 5 minutes after the session ends. The operator still opens the session from
the console using the device password. The app records **Conferma nell’app** as the
last activation channel; it sends no SMS/Telegram wake receipt to the server.

There is no prompt while continuous mode is ON, the agent is connecting, online,
in a session or reconnecting, or control is paused. The offer waits for pairing
and accessibility to be ready. Declining or dismissing it suppresses it for that
opening, including screen rotation; leave and reopen the app to ask again. If an
SMS or Telegram activation arrives while the dialog is visible, the dialog closes
without opening a second connection or extending the existing window.

## SMS and Telegram activation

**Mantieni connessione al server** defaults to OFF, including after an upgrade without a saved preference. Until a local confirmation or wake command, the agent waits locally, with no server socket, heartbeat or polling. Enable it to keep the old continuous connection behavior.

1. Ensure the server has `MYDESK_ENCRYPTION_KEY` configured. Pairing or the first run of an upgraded agent provisions its wake key without changing the existing pairing. A failed setup remains visible; use **Riprova configurazione attivazione** after correcting it. No automatic retry loop runs.
2. For SMS, tap **Abilita ricezione SMS** and grant the permission. Use a SIM that can receive SMS. Android classifies `RECEIVE_SMS` as hard restricted: the APK installer must allowlist it as well as the user granting it. Verify your enterprise installation procedure on the actual device; no inbox-reading or SMS-sending permission is requested.
3. For Telegram, tap **Abilita accesso notifiche Telegram** and allow RemotePocket. The official Telegram/Telegram X app must receive and publish the message text in its notification. There is no installation check and no bot requirement. Disabled notifications, hidden previews, an open conversation, work-profile restrictions or delivery suppression can prevent activation.
4. On sideloaded APKs, Android may require **Allow restricted settings** in app information before accessibility/notification access can be enabled. Exclude RemotePocket from battery optimization using the app's settings button; verify any additional manufacturer background restrictions during provisioning.

Once setup is complete, **In attesa di connessione dall’app, SMS o Telegram** is the expected idle state with continuous connection OFF. The console can show the device as offline while it is waiting. You may enable either reception channel or both; no preferred-channel selection is required.

### Each time support is needed

1. In the console, choose **Attiva tramite SMS o Telegram** on the target device, then **Copia**. The console generates a signed command but does not send it.
2. For **SMS**, send exactly that text, without additions, to the target device's SIM number. Make sure the messaging app sends an SMS, not RCS or another chat format.
3. For **Telegram** instead, paste the same text into a conversation with the account used on the target Android device. Telegram must produce a notification containing it there. Opening the chat on another computer is not enough, and the recipient does not need to tap the notification.
4. Wait for the console to report the device online. Enter its device password and choose **Apri sessione**. The wake message enables a connection; session authentication remains required.

The command must be received before its expiry, ten minutes after generation. Once accepted, it opens a separate ten-minute connection window measured from receipt. The same command can activate only once, even across restarts or delivery through both channels. Neither sender name nor phone number replaces signature verification. The app shows the last activation channel; subsequent screen images and input travel through the RemotePocket server.

No local tap is needed to connect. The device still needs internet for the server connection, and accessibility must already be enabled. If no session starts, connection attempts stop 10 minutes after receipt. After a session ends or loses its connection, the agent remains available/retries for at most 5 minutes; a new session cancels that deadline. Additional messages while awake do not extend it. A reboot returns on-demand mode to local waiting.

Turning continuous mode OFF disconnects immediately when idle, or 5 minutes after the current session ends. Pausing always disconnects and ignores wake messages. A wake command does not unlock the screen, enable accessibility, or bypass the device password.

See the [complete workflow, timing example, troubleshooting and hardware checklist](../Server/docs/wake-activation.md).

## Server address

| Setup | URL to enter in the app |
| --- | --- |
| Android Studio emulator, server on your computer | `http://10.0.2.2:8000` |
| Physical device on the same network | `http://<computer-lan-ip>:8000` |
| Deployed server | `https://<your-domain>` |

For a physical device, start the development server with `--host 0.0.0.0`, connect both devices to the same network and allow inbound port 8000 on the computer. Do not enter `localhost` as the phone's server address.

Debug builds allow HTTP for local development. Release builds require HTTPS with a trusted certificate.

## During a session

Keep the device unlocked and the accessibility service enabled. The console can display screenshots, send taps and swipes, enter text in supported fields and use Android navigation buttons. Text input depends on the app and field being controlled.

Use the pause button in RemotePocket Agent to disconnect and stop remote control. The pause stays active after a restart; resume restores local waiting or the continuous connection, according to the saved preference. Removing the local configuration lets you pair again. To revoke access on the server, use the device's revoke button in the console.

If the network connection drops, the app tries to reconnect. Open a new remote session once it is online again. Invalid or revoked credentials require a new pairing.

## Troubleshooting

| Problem | Check |
| --- | --- |
| Gradle cannot find Java or the SDK | Select JDK 17 and check `JAVA_HOME`, `ANDROID_HOME` or `local.properties`. |
| Pairing fails | Check the server address, network, unused pairing code and device password length. Generate a new code if it has expired. |
| Device is offline while waiting | This is normal with continuous connection OFF. Open the app and choose **Connetti**, or send a fresh signed SMS or Telegram message, then wait for online presence. |
| Device stays offline after a wake message | Check expiry, SMS permission or Telegram notification text/access, accessibility, pause, internet and battery restrictions. See the [activation troubleshooting guide](../Server/docs/wake-activation.md#if-activation-does-not-work). |
| No screenshots | Use Android 11 or newer, enable accessibility and keep the device unlocked. |
| HTTP URL is rejected | Install a debug build for local HTTP testing, or use an HTTPS server. |

## Tests

```bash
./gradlew :app:testDebugUnitTest
```

On Windows, use `.\gradlew.bat :app:testDebugUnitTest`.
