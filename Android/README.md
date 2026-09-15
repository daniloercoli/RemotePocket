# MyDesk Android app

The Android app connects a device to the MyDesk server. It uses an accessibility service to capture the screen and handle remote input.

## Requirements

- Android Studio, JDK 17 and Android SDK Platform 35.
- An Android device or emulator. Screen capture requires Android 11 / API 30 or newer. The minimum install version is Android 8 / API 26.
- A running [MyDesk server](../Server/README.md).

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

On Windows, use `.\gradlew.bat :app:installDebug`. Open **MyDesk Agent** from the device's app list after installation.

## Pair with the server

1. Open the web console on your computer and log in. On a new server, create the first owner account first.
2. Create a pairing code in the console. It has 8 characters, works once and expires after 10 minutes by default.
3. In MyDesk Agent, enter the server URL, a device name, the code and a device password of at least 8 characters.
4. Tap the pairing button.
5. Open accessibility settings from the app and enable **MyDesk Remote Control**.
6. Return to the console. Once the device is online, enter its device password and open a session.

The device password is separate from the account password. The app does not save the pairing code or device password. It saves the server URL, device ID and name, and stores the device token encrypted with Android Keystore.

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

Use the pause button in MyDesk Agent to disconnect and stop remote control. The pause stays active after a restart; use the resume button to reconnect. Removing the local configuration lets you pair again. To revoke access on the server, use the device's revoke button in the console.

If the network connection drops, the app tries to reconnect. Open a new remote session once it is online again. Invalid or revoked credentials require a new pairing.

## Troubleshooting

| Problem | Check |
| --- | --- |
| Gradle cannot find Java or the SDK | Select JDK 17 and check `JAVA_HOME`, `ANDROID_HOME` or `local.properties`. |
| Pairing fails | Check the server address, network, unused pairing code and device password length. Generate a new code if it has expired. |
| Device stays offline | Enable the accessibility service, resume control if paused and check the server is reachable. |
| No screenshots | Use Android 11 or newer, enable accessibility and keep the device unlocked. |
| HTTP URL is rejected | Install a debug build for local HTTP testing, or use an HTTPS server. |

## Tests

```bash
./gradlew :app:testDebugUnitTest
```

On Windows, use `.\gradlew.bat :app:testDebugUnitTest`.
