# RemotePocket

RemotePocket lets you control mobile devices from a web browser. The current version supports Android and includes a Python server, a web console and an Android app. Use it on devices you own or have permission to manage.

## What you need

- Python 3.12 for the server.
- Android Studio, JDK 17 and Android SDK 35 for the mobile app.
- An Android 11 or newer device or emulator for screen capture. The app also installs on Android 8–10, but screenshots are unavailable.

The web console is served by the backend. It does not need a separate build or web server.

## Start the server

From the repository folder, on macOS or Linux:

```bash
cd Server
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2'
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
cp .env.example .env
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Copy `.env.example` only on the first setup. Keep your existing `.env` on later runs.

Open [the console](http://localhost:8000/) on the computer running the server. Enter a username and a strong password, then use the button to create the first owner account. Email is optional. On later visits, log in with the same account.

Usernames must be 3–30 letters, numbers or underscores. Account passwords need at least 8 characters, uppercase and lowercase letters, a number and a symbol. Common, weak or breached passwords are rejected. The server needs internet access for the password breach check.

This setup uses a local SQLite database. Docker, PostgreSQL and Redis are not needed for the default development setup. `0.0.0.0` makes the server reachable from your local network; use `127.0.0.1` if you only need access from the computer itself.

For Windows commands, configuration and HTTPS deployment, see the [server guide](Server/README.md).

## Run the mobile app

1. Open the `Android` folder in Android Studio.
2. Set the Gradle JDK to 17 and install Android SDK Platform 35 in the SDK Manager.
3. Connect an Android device with USB debugging enabled, or start an Android 11 or newer emulator.
4. Select the `app` run configuration and click **Run** to install and open the debug app.

You can also build and install it from a terminal on macOS or Linux:

```bash
cd Android
./gradlew :app:installDebug
```

On Windows, use `.\gradlew.bat :app:installDebug`. Open **MyDesk Agent** on the device after installation. See the [Android guide](Android/README.md) for SDK setup and APK builds.

## Connect the device

1. In the web console, create a pairing code.
2. In the Android app, enter the server URL, a device name, the pairing code and a device password of at least 8 characters.
3. Pair the device, then open accessibility settings from the app and enable **MyDesk Remote Control**.
4. Return to the console and wait for the device to appear online.
5. Enter the device password on its card and open a remote session.

Use the right server URL in the app:

| Device | Server URL |
| --- | --- |
| Android Studio emulator | `http://10.0.2.2:8000` |
| Phone on the same local network | `http://<computer-lan-ip>:8000` |
| HTTPS deployment | `https://<your-domain>` |

`localhost` on the phone refers to the phone itself. For a physical device, use the computer's local IP address and allow port 8000 through its firewall. HTTP works only in debug builds; release builds require HTTPS with a trusted certificate.

Pairing codes are single-use and expire after 10 minutes by default. Keep the device password: it is separate from your account password and is needed to open remote sessions.

The console supports taps, swipes, text input and the Back, Home and Recent apps buttons. Keep the device unlocked. You can close a session from the console or pause control from the Android app.

## More information

- [Server setup and operation](Server/README.md)
- [Android setup and use](Android/README.md)
- [Monitoring alerts](Server/docs/alert-rules.md)
- [Development Redis relay](Server/docs/websocket-relay.md)
- [Security policy](SECURITY.md)
- [Static website](Website/README.md)

Run the backend with one worker and one instance. Live device connections and remote sessions are managed by that process.

## License

RemotePocket is free software, licensed under the GNU General Public License, version 3 or, at your option, any later version (`GPL-3.0-or-later`). It is distributed without any warranty. See [LICENSE](LICENSE) for the full terms. Third-party components retain their own licenses and notices.
