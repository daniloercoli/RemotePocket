# MyDesk server

The server runs the API, the web console and the connection to Android devices. It uses FastAPI and serves the console directly, with no separate frontend build.

Run one backend instance with one worker. Device connections and remote sessions live in that process.

## Local setup

Use Python 3.12. Run the following commands from the repository folder on macOS or Linux:

```bash
cd Server
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2'
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
cp .env.example .env
```

Copy `.env.example` only when setting up a new environment. Keep an existing `.env` when restarting or updating the app. If pip needs to compile `cryptography` from source, Rust and OpenSSL build dependencies are required.

On Windows, in PowerShell:

```powershell
cd Server
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade 'pip>=26.2'
python -m pip install -e .
Copy-Item .env.example .env
```

The runtime lock is generated for Python 3.12 on Unix. The Windows setup installs dependencies from `pyproject.toml` directly.

On every platform, generate a signing key once:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Save the result as `MYDESK_SECRET_KEY` in `.env`, then start the server:

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The key is required in all environments, including development. Missing, blank or short keys and the old development placeholder prevent startup. Keep the generated key across restarts. When upgrading an installation that used the old placeholder, replace it before restarting; changing the key invalidates existing access tokens.

Open [the console](http://localhost:8000/) on the server computer. The default setup uses SQLite in `Server/mydesk.db` and an in-memory rate limiter, so Docker and Redis are not required. Use `--host 127.0.0.1` if access is only needed from the computer itself.

After the initial setup, activate the virtual environment and run the same Uvicorn command to start the server again. Stop it with `Ctrl+C`.

## First account and mobile connection

Enter a username and a strong password in the console, then create the first owner account. Email is optional. Usernames allow 3–30 letters, numbers or underscores. Account passwords need at least 8 characters, uppercase and lowercase letters, a number and a symbol. Weak, common and breached passwords are rejected.

Log in, generate a pairing code and follow the [Android setup guide](../Android/README.md). The code is single-use and expires after 10 minutes by default. Set a separate device password in the app and use that password to open sessions from the console.

Opening a device session requires browser Web Crypto: open the console over HTTPS or on `localhost`. Plain HTTP at a LAN IP does not provide this browser capability.

For a phone on the same network, use `http://<computer-lan-ip>:8000` in the app and allow port 8000 through the computer's firewall. For the Android Studio emulator, use `http://10.0.2.2:8000`. Local HTTP requires a debug build of the Android app.

If you also open the web console using the computer's LAN address, add that browser origin to `.env` and restart the server. Replace the example address with your own:

```dotenv
MYDESK_CORS_ALLOWED_ORIGINS=http://localhost:8000,http://192.168.1.10:8000
```

Origins include the scheme and port, with no path or trailing slash. This setting also controls browser WebSocket access.

## Configuration

Settings use the `MYDESK_` prefix and are read from the environment or `.env` in the working directory. See [.env.example](.env.example) for common settings and [app/config.py](app/config.py) for the full list. Restart the server after changing them.

| Setting | Default | Purpose |
| --- | --- | --- |
| `MYDESK_ENVIRONMENT` | `dev` | Select `dev`, `staging` or `prod`. |
| `MYDESK_DATABASE_URL` | `sqlite+pysqlite:///./mydesk.db` | Database connection. PostgreSQL uses the synchronous `postgresql+psycopg2` driver. |
| `MYDESK_SECRET_KEY` | None; required | Signing key for access tokens. Configure a random secret of at least 32 characters in every environment. |
| `MYDESK_CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:8000` | Allowed browser origins, separated by commas. |
| `MYDESK_ACCESS_TOKEN_TTL_MINUTES` | `60` | Access token lifetime. |
| `MYDESK_REFRESH_TOKEN_TTL_DAYS` | `30` | Maximum login session lifetime. |
| `MYDESK_MAX_CONCURRENT_SESSIONS` | `3` | Login sessions allowed per account. |
| `MYDESK_MAX_REMOTE_SESSIONS` | `3` | Simultaneous remote sessions per account. |
| `MYDESK_MAX_CONSOLE_CONNECTIONS` | `6` | Live and pending console connections per account, shared across login sessions. |
| `MYDESK_MAX_WEBSOCKET_CONNECTIONS` | `1000` | Total device and console connections, including pending handshakes. |
| `MYDESK_RATE_LIMIT_WS_UPGRADE` | `30` | WebSocket handshake attempts per IP per minute, shared between both endpoints. |
| `MYDESK_RATE_LIMIT_WS_CONTROL` | `600` | Control messages per minute per console owner or device. |
| `MYDESK_RATE_LIMIT_WS_CONTROL_PER_SECOND` | `30` | Control messages per connection in a rolling second, checked before shared storage, database queries or JSON parsing. |
| `MYDESK_MAX_SCREEN_FRAMES_PER_SECOND` | `30` | Frames allowed per device in a rolling second. |
| `MYDESK_MAX_SCREEN_BYTES_PER_SECOND` | `10000000` | Screen bytes allowed per device in a rolling second; maximum packet size is 5 MB. |
| `MYDESK_MONITORING_TOKEN` | Empty | Independent bearer token for metrics and detailed health. Empty disables access. |
| `MYDESK_CHECK_PASSWORD_BREACHES` | `true` | Check account passwords against breached passwords. |

The password breach check needs access to `api.pwnedpasswords.com`. If the service is unavailable, account creation and password reset return an error and can be retried later.

Device-list requests share a 30-per-minute account budget across HTTP and WebSocket. Exceeding connection, control-message or streaming budgets closes the WebSocket with code `4429`; rate-limit storage failure closes it with `1013`. These codes allow Android to reconnect without discarding its pairing.

Each console and device connection also has a local control-message limiter. Malformed messages count, including unexpected binary messages sent by consoles. Device screen frames use their separate frame/byte budgets. These local resource limits remain active when shared rate limiting is disabled in development. Reconnecting resets the local window but does not reset the shared account/device budget.

WebSocket writes time out after 5 seconds if the transport stalls. Session cleanup is committed before notifying peers, so a slow connection cannot hold database locks during disconnection.

Device session authentication uses a [challenge-response proof](docs/device-authentication.md). The console clears the password field and sends a proof instead of the password. Challenges expire after 60 seconds and can be used once on the issuing console connection. HTTPS/WSS remains required in staging and production.

Reusing a consumed refresh token revokes that login session and all its tokens. The console coordinates renewals across tabs with Web Locks and shares rotated credentials atomically. Use HTTPS or localhost for automatic renewal. When Web Locks are unavailable, or a renewal response is lost, sign in again; an uncertain renewal is not automatically replayed.

Login sessions record a fingerprint of the client IP and User-Agent. A changed fingerprint is audited at refresh and becomes the new baseline; ordinary HTTP and WebSocket authentication does not compare it. This permits network and browser changes without forcing logout. The fingerprint is a diagnostic signal, not device authentication: a stolen bearer token can still be replayed while its session is valid. IP and User-Agent binding alone cannot reliably prevent this, as described in the [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#binding-the-session-id-to-other-user-properties).

HTTP responses include CSP, frame protection, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and a Permissions Policy disabling camera, microphone and geolocation in the console browser. HSTS is sent only over HTTPS. The production nginx configuration also applies these protections to redirects and proxy-generated errors, preserves the application's CSP without duplicate headers, and uses a restrictive CSP when the application supplies none.

In staging and production, the server requires PostgreSQL, Redis, HTTPS, valid signing and encryption keys, explicit HTTPS origins and enabled security checks. Files in `/run/secrets` named after settings take precedence over environment variables and `.env`.

### Optional local PostgreSQL

From `Server`, with the virtual environment active, on macOS or Linux:

```bash
export MYDESK_DEV_DB_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up -d --wait
export MYDESK_DATABASE_URL="postgresql+psycopg2://mydesk:${MYDESK_DEV_DB_PASSWORD}@localhost:5432/mydesk_dev"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

This Compose file starts PostgreSQL and Redis only; run the Python server separately. Both services bind to localhost. Keep the generated database password in your local configuration for later runs. An existing PostgreSQL volume keeps its original password.

### Email and two-factor authentication

Basic login and remote control work without SMTP. To enable two-factor authentication, generate a Fernet key once and save it as `MYDESK_ENCRYPTION_KEY` in `.env`:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

For email verification and password recovery, also set:

```dotenv
MYDESK_PUBLIC_BASE_URL=https://desk.example.com
MYDESK_SMTP_HOST=smtp.example.com
MYDESK_SMTP_PORT=587
MYDESK_SMTP_FROM=mydesk@example.com
MYDESK_SMTP_USERNAME=your-smtp-user
MYDESK_SMTP_PASSWORD=your-smtp-password
MYDESK_SMTP_TLS=starttls
```

Replace these values with your server and SMTP settings. `MYDESK_PUBLIC_BASE_URL` must be the address users can open from email links. `ssl` is also supported; unencrypted SMTP is allowed only on localhost in development.

Accounts need a verified email address to recover a password by email. Two-factor authentication is managed in the console's account settings. Save the recovery codes when they are shown.

Keep the encryption key across restarts and back it up separately from the database. It protects stored two-factor secrets and queued email. Replacing it does not re-encrypt existing data.

## Deploy with Docker and HTTPS

The production stack includes the app, PostgreSQL, Redis and nginx. It requires a Linux host with Docker Compose v2, a domain pointing to the host and a trusted TLS certificate. Run the commands from `Server` with access to Docker and `sudo` for host configuration.

Create the secret files once:

```bash
sudo python3 - <<'PYTHON'
import base64
from pathlib import Path
import secrets

root = Path('/etc/mydesk/secrets')
root.mkdir(parents=True, exist_ok=True, mode=0o700)
root.chmod(0o700)
password = secrets.token_urlsafe(32)
values = {
    'postgres_password': password,
    'MYDESK_SECRET_KEY': secrets.token_urlsafe(48),
    'MYDESK_ENCRYPTION_KEY': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    'MYDESK_SMTP_PASSWORD': '',
    'MYDESK_DATABASE_URL': f'postgresql+psycopg2://mydesk_user:{password}@postgres:5432/mydesk_prod',
}
for name, value in values.items():
    with (root / name).open('x') as file:
        file.write(value)
    (root / name).chmod(0o444)
PYTHON
```

The script refuses to overwrite existing files. The parent directory restricts host access; the files are readable by the app container's UID 1000 and mounted read-only. Keep the database password and the password in its connection URL in sync. Changing a secret file does not change the password inside an existing PostgreSQL database.

Place your certificate chain at `/etc/mydesk/tls/fullchain.pem` and private key at `/etc/mydesk/tls/privkey.pem`, keeping the private key protected on the host. Use actual files in that directory: certificate symlinks pointing outside it will not resolve inside the container. The directory is mounted read-only into nginx.

Set your domain and deployment paths, then start the stack:

```bash
export MYDESK_DOMAIN=desk.example.com
export MYDESK_SECRETS_DIR=/etc/mydesk/secrets
export MYDESK_TLS_DIR=/etc/mydesk/tls
export MYDESK_ACME_DIR=/var/www/certbot
sudo mkdir -p "$MYDESK_ACME_DIR"
docker compose -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.prod.yml up -d --build --wait
curl --fail "https://${MYDESK_DOMAIN}/api/health"
```

Replace `desk.example.com` with your domain. Keep these variables in your deployment environment for later Compose commands. Open `https://<your-domain>` for the console and use the same URL in the Android app.

Only nginx publishes host ports, 80 and 443. The app, database and Redis have no public host ports. Allow HTTP and HTTPS through the firewall. Keep one app instance and one worker.

The stack does not issue or renew certificates. Configure renewal with your certificate provider. The HTTP ACME challenge path is served from `MYDESK_ACME_DIR`. After renewal, update the files in the TLS directory and reload nginx:

```bash
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload
```

To enable email in this stack, set the SMTP environment variables described above and put the SMTP password in `/etc/mydesk/secrets/MYDESK_SMTP_PASSWORD`. An empty file is valid when SMTP is unused or does not need a password. Recreate the app container after changing environment settings or secrets.

## Database and backups

A fresh database is initialized automatically. Existing databases must already use the current schema: older or incomplete schemas are rejected, and automatic upgrades or SQLite-to-PostgreSQL conversion are not provided. Back up an existing database before changing its configuration.

Users, devices and account history survive restarts. Active remote sessions end when the server stops; devices reconnect and a new session can be opened from the console.

Install `age` on the machine running the backup scripts (`apt-get install age` on Ubuntu or `brew install age` on macOS). Generate an identity with `age-keygen -o backup-identity.txt` on a trusted recovery machine and keep this private file separately from backups and the server. Obtain its public recipient with `age-keygen -y backup-identity.txt`.

From `Server`, with the production Compose variables set:

```bash
export MYDESK_BACKUP_AGE_RECIPIENT='age1...your-public-recipient...'
./scripts/backup.sh /absolute/path/to/backups

# Only restore/recovery checks need the separate private identity.
export MYDESK_BACKUP_AGE_IDENTITY_FILE=/secure/path/backup-identity.txt
./scripts/test-recovery.sh /absolute/path/to/backups/backup.sql.gz.age
```

Use the actual file created by `backup.sh` for the recovery check. It restores into a temporary, separate PostgreSQL container. Backups are complete SQL dumps compressed and encrypted in a streaming pipeline with age (no plaintext backup is written to disk), with daily retention of 7 days and weekly retention of 28 days by default.

For an actual restore, use an empty destination database and have the original encryption key and deployment secrets in place:

```bash
./scripts/restore.sh /absolute/path/to/backups/backup.sql.gz.age
```

Restore and recovery accept only encrypted archives. They authenticate and decompress-check the entire archive before contacting Docker, using a temporary directory accessible only to the current user, removed on exit. The temporary decrypted archive requires trusted local storage. After successful verification, the restore script stops the app, refuses a non-empty database and restarts the app after a successful restore. On failure, the app stays stopped. Keep a copy of database backups and the separately stored encryption key outside the server.

The [systemd examples](ops/systemd) can schedule daily backups and weekly recovery checks. Set their installation paths and `/etc/mydesk/backup.env` before enabling the timers. That environment file must define `MYDESK_BACKUP_AGE_RECIPIENT`; the recovery job also needs `MYDESK_BACKUP_AGE_IDENTITY_FILE`. Keep the recovery identity on a separate trusted recovery host where possible. Losing that identity makes the archives unrecoverable. Retention applies only to `.sql.gz.age` archives.

## Health, logs and API

| Path | Purpose |
| --- | --- |
| `/` | Web console. |
| `/api/docs` | Interactive API reference when `MYDESK_DEBUG=true`. |
| `/api/health` | Basic service health. |
| `/api/health/ready` | Readiness of the database, rate limiter and relay if enabled; monitoring token required. |
| `/api/health/advanced` | Detailed health, including disk space; monitoring token required. |
| `/metrics` | Prometheus metrics when enabled; monitoring token required. |
| `/console/ws` | Console WebSocket connection. |
| `/device/ws` | Android WebSocket connection. |

Application logs use JSON and include request IDs. nginx access logs contain method, path, status, size and client IP, excluding query strings and headers. Per-server nginx error logging is disabled because it cannot redact request URLs; use access status codes and application logs to investigate request failures. Global nginx startup/configuration diagnostics remain available. Set `MYDESK_LOG_LEVEL` to control verbosity. Metrics collection is enabled by default, but access to `/metrics`, `/api/health/ready` and `/api/health/advanced` requires `Authorization: Bearer <MYDESK_MONITORING_TOKEN>`. Configure a separate random token of at least 32 characters; account access tokens do not grant monitoring access. With an empty monitoring token, these endpoints return 404 from the app. nginx rejects anonymous diagnostic requests with 401 before proxying them. `/api/health` remains public and the Docker health check keeps working without monitoring credentials.

The production Compose file accepts `MYDESK_MONITORING_TOKEN` from the deployment environment. Settings also support a mounted `/run/secrets/MYDESK_MONITORING_TOKEN` file, which takes precedence if you add it to your Compose secret mounts. Configure the same token in Prometheus using a protected credentials file; see the [alert setup](docs/alert-rules.md). Existing Prometheus installations must add this credential when upgrading. A tracing endpoint is optional: an empty `MYDESK_TRACING_ENDPOINT` sends no traces to an external collector.

The [Redis relay](docs/websocket-relay.md) is available for development only. Staging and production require `MYDESK_REDIS_RELAY_ENABLED=false`.

## Tests

With the virtual environment active, install the development tools and run the backend and console tests from `Server`. The console tests require Node.js. Backup tests require `age` and `age-keygen`.

```bash
python -m pip install -e '.[dev,security]'
python -m pytest -q
node --test tests/*.test.cjs
```

To run the backend suite against PostgreSQL, set `MYDESK_TEST_POSTGRES_URL` to a dedicated test database. Redis relay tests use a local `redis-server` or `MYDESK_TEST_REDIS_URL` pointing to a test instance.

The repository also includes these checks:

```bash
./scripts/security-check.sh
./scripts/scan-secrets.sh
./scripts/test-production.sh
```

The secret scan and production smoke test require Docker. The production test uses temporary containers and certificates on ports 58080 and 58443, then removes its own containers and volumes.
