#!/usr/bin/env bash
# Isolated production smoke test. Never mounts an existing database or real secrets.
set -euo pipefail
unset BACKUP_NOTIFICATION_WEBHOOK
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/mydesk-production.XXXXXX")
export MYDESK_DOMAIN=localhost
export MYDESK_SECRETS_DIR="$test_dir/secrets"
export MYDESK_TLS_DIR="$test_dir/tls"
export MYDESK_ACME_DIR="$test_dir/acme"
export MYDESK_HTTP_PORT=${MYDESK_HTTP_PORT:-58080}
export MYDESK_HTTPS_PORT=${MYDESK_HTTPS_PORT:-58443}
# Keep the smoke test independent of host monitoring and backup destinations.
export MYDESK_METRICS_ENABLED=true
export MYDESK_MONITORING_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MYDESK_TRACING_ENABLED=true
export MYDESK_SMTP_HOST=
export MYDESK_SMTP_FROM=
export MYDESK_SMTP_USERNAME=
export MYDESK_SMTP_TLS=starttls
export MYDESK_TRACING_ENDPOINT=
export MYDESK_TRACING_PROTOCOL=http
export MYDESK_TRACING_INSECURE=false
export MYDESK_BACKUP_TEST_RECOVERY=false
mkdir -p "$MYDESK_SECRETS_DIR" "$MYDESK_TLS_DIR" "$MYDESK_ACME_DIR"
export COMPOSE_PROJECT_NAME="mydesk-review-$$"
compose=(docker compose --env-file /dev/null -p "$COMPOSE_PROJECT_NAME" -f docker-compose.prod.yml)
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then "${compose[@]}" logs --tail=100; fi
    "${compose[@]}" down --volumes --remove-orphans
    rm -rf "$test_dir"
    exit "$status"
}
trap cleanup EXIT
python3 - <<'PY'
import os
from pathlib import Path
import secrets
root = Path(os.environ['MYDESK_SECRETS_DIR'])
password = secrets.token_urlsafe(32)
(root / 'postgres_password').write_text(password)
(root / 'MYDESK_SECRET_KEY').write_text(secrets.token_urlsafe(48))
import base64
(root / 'MYDESK_ENCRYPTION_KEY').write_text(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
(root / 'MYDESK_SMTP_PASSWORD').write_text('')
(root / 'MYDESK_DATABASE_URL').write_text(
    f'postgresql+psycopg2://mydesk_user:{password}@postgres:5432/mydesk_prod')
PY
# Disposable certificate only: deployment must use a publicly trusted certificate.
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout "$MYDESK_TLS_DIR/privkey.pem" -out "$MYDESK_TLS_DIR/fullchain.pem" \
  -subj '/CN=localhost' >/dev/null 2>&1
"${compose[@]}" config --quiet
"${compose[@]}" up -d --build --wait --wait-timeout 180
"${compose[@]}" exec -T nginx nginx -t
# Run checks inside the built image so the test has no host Python dependencies.
"${compose[@]}" exec -T app python - <<'PY'
import httpx
import json
import ssl
from websockets.sync.client import connect
from app.main import app
from app.auth_service import AuthService
from app.models import User
from app.security import hash_password
from app.timeutils import utc_now

# Test credentials only, inserted through a trusted database session.
with app.state.SessionLocal() as db:
    db.add(User(id='smoke-user', username='smoke', password_hash=hash_password('Violet!Harbor7Lantern')))
    db.commit()

# Test-only self-signed certificate in this disposable stack.
with httpx.Client(base_url='https://nginx', verify=False, timeout=10) as client:
    health = client.get('/api/health')
    assert health.status_code == 200, health.text
    assert health.json() == {'status': 'ok'}
    monitoring = {'Authorization': 'Bearer ' + app.state.settings.monitoring_token}
    for path in ('/metrics', '/api/health/ready', '/api/health/advanced'):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={'Authorization': 'Bearer invalid-monitor'}).status_code == 401
        assert client.get(path, headers=monitoring).status_code == 200
    metrics = client.get('/metrics', headers=monitoring)
    assert metrics.status_code == 200 and 'http_requests_total' in metrics.text
    assert health.headers['x-request-id']
    assert 'max-age=31536000' in health.headers['strict-transport-security']
    assert "img-src 'self' blob:" in client.get('/').headers['content-security-policy']
    assert client.get('/api/openapi.json').status_code == 404
    login = client.post('/api/auth/login', json={'username': 'smoke', 'password': 'Violet!Harbor7Lantern'})
    assert login.status_code == 200, login.text
    tokens = login.json()
    headers = {'Authorization': 'Bearer ' + tokens['access_token']}
    assert client.get('/metrics', headers=headers).status_code == 401
    assert client.get('/api/auth/me', headers=headers).status_code == 200
    assert client.get('/api/auth/config').json()['totp_available'] is True
    assert client.get('/api/activity/summary', headers=headers).status_code == 200
    code = client.post('/api/pairing-codes', headers=headers).json()['code']
    paired = client.post('/api/devices/pair', json={'pairing_code': code, 'name': 'Smoke device',
                                                  'device_password': 'smoke-device-password'}).json()
    tls = ssl._create_unverified_context()  # Disposable self-signed test certificate.
    with connect('wss://nginx/console/ws', ssl=tls, origin='https://localhost',
                 subprotocols=['mydesk', 'bearer.' + tokens['access_token']]) as ws:
        assert json.loads(ws.recv(timeout=5))['type'] == 'console_registered'
        with connect('wss://nginx/device/ws?device_id=' + paired['device_id'], ssl=tls,
                     additional_headers={'Authorization': 'Bearer ' + paired['device_token']}) as device:
            assert json.loads(device.recv(timeout=5))['type'] == 'device_registered'
            ws.send(json.dumps({'type': 'session_start_request', 'deviceId': paired['device_id'],
                                'devicePassword': 'smoke-device-password'}))
            sid = json.loads(device.recv(timeout=5))['sessionId']
            assert json.loads(ws.recv(timeout=5))['type'] == 'session_started'
            frame = json.dumps({'type': 'screen_frame', 'sessionId': sid, 'frameId': 1,
                                'width': 1, 'height': 1, 'format': 'jpeg'}).encode()
            packet = len(frame).to_bytes(4, 'little') + frame + bytes([255, 216, 255, 217])
            device.send(packet)
            assert ws.recv(timeout=5) == packet
    assert client.post('/api/auth/logout', headers=headers, json={'refresh_token': tokens['refresh_token']}).status_code == 200
    assert client.get('/api/auth/me', headers=headers).status_code == 401
    for _ in range(4):
        assert client.post('/api/auth/login', json={'username': 'missing', 'password': 'wrong-password'}).status_code == 401
    response = client.post('/api/auth/login', json={'username': 'missing', 'password': 'wrong-password'},
                           headers={'X-Forwarded-For': '192.0.2.9'})
    assert response.status_code == 429, response.text
    assert 'retry-after' in response.headers
redirect = httpx.get('http://nginx/api/health', follow_redirects=False)
assert redirect.status_code == 301
assert redirect.headers['location'] == 'https://localhost/api/health'
print('Production smoke: HTTPS, HSTS, secrets, PostgreSQL, Redis limits, WSS binary relay, login and logout passed')
PY

# These backups use only the disposable production-smoke Compose project above.
bash scripts/backup.sh "$test_dir/backups"
backup_files=("$test_dir"/backups/*.sql.gz)
bash scripts/test-recovery.sh "${backup_files[0]}"
