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
import asyncio
import base64
import hashlib
import hmac
import httpx
import json
import secrets
import ssl
from websockets.asyncio.client import connect
from app.main import app
from app.auth_service import AuthService
from app.models import User
from app.security import hash_password
from app.timeutils import utc_now


def check_security_headers(response, *, edge=False, https=True):
    expected = {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=(), microphone=(), geolocation=()',
        'cache-control': 'no-store',
        'content-security-policy': (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            if edge else app.state.settings.content_security_policy
        ),
    }
    if not https:
        expected.pop('strict-transport-security')
        assert 'strict-transport-security' not in response.headers
    for name, value in expected.items():
        assert response.headers.get_list(name) == [value], (response.status_code, name, response.headers.get_list(name))


async def check_websocket_relay(tokens, paired):
    # Keep TLS I/O on one event loop; connect directly to this disposable stack.
    tls = ssl._create_unverified_context()  # Disposable self-signed test certificate.
    print('Production smoke: opening console WebSocket through nginx', flush=True)
    async with connect('wss://nginx/console/ws', ssl=tls, origin='https://localhost',
                       subprotocols=['mydesk', 'bearer.' + tokens['access_token']],
                       proxy=None, open_timeout=10) as ws:
        assert ws.subprotocol == 'mydesk'
        assert json.loads(await asyncio.wait_for(ws.recv(), timeout=5))['type'] == 'console_registered'
        print('Production smoke: console registered; opening device WebSocket', flush=True)
        async with connect('wss://nginx/device/ws?device_id=' + paired['device_id'], ssl=tls,
                           additional_headers={'Authorization': 'Bearer ' + paired['device_token']},
                           proxy=None, open_timeout=10) as device:
            assert json.loads(await asyncio.wait_for(device.recv(), timeout=5))['type'] == 'device_registered'
            print('Production smoke: device registered; checking binary relay', flush=True)
            await ws.send(json.dumps({'type': 'session_challenge_request', 'deviceId': paired['device_id'],
                                      'clientNonce': secrets.token_hex(32)}))
            challenge = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert challenge['type'] == 'session_challenge'
            salted = hashlib.pbkdf2_hmac('sha256', b'smoke-device-password',
                                        base64.b64decode(challenge['salt']), challenge['iterations'])
            client_key = hmac.digest(salted, b'Client Key', 'sha256')
            nonce = challenge['nonce']
            transcript = (f"n={paired['device_id']},r={challenge['clientNonce']},r={nonce},"
                          f"s={challenge['salt']},i={challenge['iterations']},c=biws,r={nonce}").encode()
            signature = hmac.digest(hashlib.sha256(client_key).digest(), transcript, 'sha256')
            proof = base64.b64encode(bytes(a ^ b for a, b in zip(client_key, signature))).decode()
            await ws.send(json.dumps({'type': 'session_start_request', 'deviceId': paired['device_id'],
                                      'challengeId': challenge['challengeId'], 'proof': proof}))
            sid = json.loads(await asyncio.wait_for(device.recv(), timeout=5))['sessionId']
            started = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert started['type'] == 'session_started'
            expected = hmac.digest(hmac.digest(salted, b'Server Key', 'sha256'), transcript, 'sha256')
            assert started['serverProof'] == base64.b64encode(expected).decode()
            frame = json.dumps({'type': 'screen_frame', 'sessionId': sid, 'frameId': 1,
                                'width': 1, 'height': 1, 'format': 'jpeg'}).encode()
            packet = len(frame).to_bytes(4, 'little') + frame + bytes([255, 216, 255, 217])
            await device.send(packet)
            assert await asyncio.wait_for(ws.recv(), timeout=5) == packet


# Test credentials only, inserted through a trusted database session.
with app.state.SessionLocal() as db:
    db.add(User(id='smoke-user', username='smoke', password_hash=hash_password('Violet!Harbor7Lantern')))
    db.commit()

# Test-only self-signed certificate in this disposable stack.
with httpx.Client(base_url='https://nginx', verify=False, timeout=10) as client:
    health = client.get('/api/health')
    assert health.status_code == 200, health.text
    assert health.json() == {'status': 'ok'}
    check_security_headers(health)
    check_security_headers(client.get('/'))
    check_security_headers(client.get('/static/console.js'))
    missing = client.get('/missing')
    assert missing.status_code == 404
    check_security_headers(missing)
    oversized = client.post('/api/auth/login', content=b'x' * 65537)
    assert oversized.status_code == 413
    check_security_headers(oversized, edge=True)
    monitoring = {'Authorization': 'Bearer ' + app.state.settings.monitoring_token}
    for path in ('/metrics', '/api/health/ready', '/api/health/advanced'):
        anonymous = client.get(path)
        assert anonymous.status_code == 401
        check_security_headers(anonymous, edge=True)
        invalid = client.get(path, headers={'Authorization': 'Bearer invalid-monitor'})
        assert invalid.status_code == 401
        check_security_headers(invalid)
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
    asyncio.run(check_websocket_relay(tokens, paired))
    assert client.post('/api/auth/logout', headers=headers, json={'refresh_token': tokens['refresh_token']}).status_code == 200
    assert client.get('/api/auth/me', headers=headers).status_code == 401
    for _ in range(4):
        assert client.post('/api/auth/login', json={'username': 'missing', 'password': 'wrong-password'}).status_code == 401
    response = client.post('/api/auth/login', json={'username': 'missing', 'password': 'wrong-password'},
                           headers={'X-Forwarded-For': '192.0.2.9'})
    assert response.status_code == 429, response.text
    assert 'retry-after' in response.headers
    check_security_headers(response)
redirect = httpx.get('http://nginx/api/health', follow_redirects=False)
assert redirect.status_code == 301
assert redirect.headers['location'] == 'https://localhost/api/health'
check_security_headers(redirect, edge=True, https=False)
print('Production smoke: HTTPS, HSTS, secrets, PostgreSQL, Redis limits, WSS binary relay, login and logout passed')
PY

export MYDESK_BACKUP_AGE_IDENTITY_FILE="$test_dir/backup-identity.txt"
age-keygen -o "$MYDESK_BACKUP_AGE_IDENTITY_FILE"
export MYDESK_BACKUP_AGE_RECIPIENT="$(age-keygen -y "$MYDESK_BACKUP_AGE_IDENTITY_FILE")"
# These backups use only the disposable production-smoke Compose project above.
bash scripts/backup.sh "$test_dir/backups"
backup_files=("$test_dir"/backups/*.sql.gz.age)
bash scripts/test-recovery.sh "${backup_files[0]}"

# Verify nginx's upstream-failure response after stopping only this disposable app.
"${compose[@]}" stop app
python3 - <<'PY'
import os
import ssl
import urllib.error
import urllib.request

context = ssl._create_unverified_context()  # Disposable self-signed certificate.
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
)
url = 'https://127.0.0.1:' + os.environ['MYDESK_HTTPS_PORT'] + '/?token=mydesk-log-sensitive-marker'
try:
    # A stopped Docker peer can refuse immediately (502) or remain unreachable
    # until nginx's default 60-second connect timeout (504).
    opener.open(url, timeout=75)
except urllib.error.HTTPError as error:
    assert error.code in {502, 504}, error.code
    expected = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    }
    for name, value in expected.items():
        assert error.headers.get_all(name) == [value], (name, error.headers.get_all(name))
else:
    raise AssertionError('Expected nginx to reject the unavailable upstream')
print('Production smoke: security headers verified on nginx 401, 413 and upstream-failure errors')
PY

# nginx must not emit request secrets through inherited access or error logs.
"${compose[@]}" logs --no-color nginx > "$test_dir/nginx.log"
if grep -q 'mydesk-log-sensitive-marker' "$test_dir/nginx.log"; then
    echo 'Sensitive request marker found in nginx logs' >&2
    exit 1
fi
echo 'Production smoke: upstream-error request secrets excluded from nginx logs'
