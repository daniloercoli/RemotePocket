import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pyotp
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import func, select, text

from app.account_service import AccountService, decrypt
from app.auth_service import AuthenticationError
from app.database import create_db_engine, init_db
from app.models import (
    AuditLog,
    EmailJob,
    LoginSession,
    MfaChallenge,
    PasswordResetToken,
    User,
)
from app.security import hash_secret
from app.timeutils import utc_now
from tests.conftest import request_session, register_device, create_reset_token

PASSWORD = "Quercia!Viola7Sentiero"


@pytest.fixture
def secured(client, auth_headers):
    settings = client.app.state.settings
    settings.encryption_key = Fernet.generate_key().decode()
    settings.smtp_host = "localhost"
    settings.smtp_from = "desk@example.com"
    settings.smtp_tls = "none"
    return client, auth_headers


def enable_mfa(client, headers):
    setup = client.post(
        "/api/auth/mfa/setup", headers=headers, json={"password": PASSWORD}
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert "svg" in setup.json()["qr_svg"]
    result = client.post(
        "/api/auth/mfa/confirm",
        headers=headers,
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert result.status_code == 200, result.text
    return secret, result.json()["recovery_codes"]


def challenge(client):
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": PASSWORD}
    )
    assert response.status_code == 202
    assert "access_token" not in response.json()
    return response.json()["challenge_token"]


def test_mfa_login_replay_recovery_and_revocation(secured):
    client, headers = secured
    secret, codes = enable_mfa(client, headers)
    assert len(set(codes)) == 10 and all(len(code) >= 32 for code in codes)
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    token = challenge(client)
    with client.app.state.SessionLocal() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(LoginSession)
                .where(LoginSession.revoked_at.is_(None))
            )
            == 0
        )
    # Activation consumed the current TOTP step.
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 401
    )
    response = client.post(
        "/api/auth/mfa/verify",
        json={"challenge_token": token, "recovery_code": codes[0]},
    )
    assert response.status_code == 200
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "recovery_code": codes[1]},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": challenge(client), "recovery_code": codes[0]},
        ).status_code
        == 401
    )
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert client.get("/api/auth/me", headers=headers).json()["totp_enabled"]
    assert (
        client.post(
            "/api/auth/mfa/setup", headers=headers, json={"password": PASSWORD}
        ).status_code
        == 400
    )


def test_mfa_challenge_expiration_attempt_limit_and_reset(secured):
    client, headers = secured
    _, codes = enable_mfa(client, headers)
    token = challenge(client)
    with client.app.state.SessionLocal.begin() as db:
        item = db.scalar(
            select(MfaChallenge).where(MfaChallenge.token_hash == hash_secret(token))
        )
        item.expires_at = utc_now() - timedelta(seconds=1)
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "recovery_code": codes[0]},
        ).status_code
        == 401
    )
    token = challenge(client)
    for _ in range(5):
        assert (
            client.post(
                "/api/auth/mfa/verify",
                json={"challenge_token": token, "recovery_code": "bad"},
            ).status_code
            == 401
        )
    with client.app.state.SessionLocal() as db:
        assert (
            db.scalar(
                select(MfaChallenge).where(
                    MfaChallenge.token_hash == hash_secret(token)
                )
            ).attempts
            == 5
        )
        assert db.scalar(select(User)).failed_login_attempts == 5
    reset = create_reset_token(client, "admin")
    assert (
        client.post(
            "/api/auth/password-reset",
            json={"token": reset, "new_password": "Montagna!Gialla9Quercia"},
        ).status_code
        == 200
    )
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Montagna!Gialla9Quercia"},
    )
    assert response.status_code == 202
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "recovery_code": codes[0]},
        ).status_code
        == 401
    )


def test_recovery_code_concurrent_consumption(secured):
    client, headers = secured
    _, codes = enable_mfa(client, headers)
    tokens = [challenge(client), challenge(client)]

    def verify(token):
        with client.app.state.SessionLocal() as db:
            try:
                AccountService(db, client.app.state.settings).verify_challenge(
                    token, None, codes[0], {}
                )
                db.commit()
                return True
            except AuthenticationError:
                db.commit()
                return False

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(verify, tokens)) == [False, True]


def test_missing_encryption_key_never_bypasses_mfa(secured):
    client, headers = secured
    secret, _ = enable_mfa(client, headers)
    client.app.state.settings.encryption_key = ""
    token = challenge(client)
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).now()},
        ).status_code
        == 401
    )


def verification_token(client):
    with client.app.state.SessionLocal() as db:
        job = db.scalar(
            select(EmailJob)
            .where(EmailJob.kind == "verification", EmailJob.status == "pending")
            .order_by(EmailJob.next_attempt_at.desc())
        )
        return json.loads(decrypt(client.app.state.settings, job.payload))[
            "body"
        ].split("#verify=")[1]


def test_email_change_keeps_old_and_invalidates_reset(secured):
    client, headers = secured
    assert (
        client.post(
            "/api/auth/email-change-request",
            headers=headers,
            json={"email": "  OWNER@Example.com ", "password": PASSWORD},
        ).status_code
        == 200
    )
    token = verification_token(client)
    assert (
        client.post("/api/auth/email-verify", json={"token": token}).status_code == 200
    )
    assert (
        client.post("/api/auth/email-verify", json={"token": token}).status_code == 400
    )
    old_reset = create_reset_token(client, "admin")
    assert (
        client.post(
            "/api/auth/email-change-request",
            headers=headers,
            json={"email": "new@example.com", "password": PASSWORD},
        ).status_code
        == 200
    )
    me = client.get("/api/auth/me", headers=headers).json()
    assert me["email"] == "owner@example.com" and me["email_verified"]
    assert me["pending_email"] == "new@example.com"
    assert (
        client.post(
            "/api/auth/email-verify", json={"token": verification_token(client)}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/auth/password-reset",
            json={"token": old_reset, "new_password": "Montagna!Gialla9Quercia"},
        ).status_code
        == 400
    )


def test_email_superseded_expired_and_concurrent(secured):
    client, headers = secured
    client.post(
        "/api/auth/email-change-request",
        headers=headers,
        json={"email": "one@example.com", "password": PASSWORD},
    )
    old = verification_token(client)
    client.post("/api/auth/email-verification-request", headers=headers)
    assert client.post("/api/auth/email-verify", json={"token": old}).status_code == 400
    token = verification_token(client)

    def verify(_):
        with client.app.state.SessionLocal() as db:
            try:
                AccountService(db, client.app.state.settings).verify_email(token)
                db.commit()
                return True
            except ValueError:
                db.rollback()
                return False

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(verify, range(2))) == [False, True]


def test_outbox_unknown_retry_stable_token_and_scrubbing(secured, monkeypatch):
    client, headers = secured
    outbox = client.app.state.email_outbox
    sent = []

    def send(email, body, identifier):
        sent.append((email, body, identifier))
        if len(sent) < 3:
            raise TimeoutError("sensitive diagnostic never logged")

    monkeypatch.setattr(outbox, "send", send)
    for email in ["missing@example.com", "unverified@example.com"]:
        assert (
            client.post(
                "/api/auth/password-reset-request", json={"email": email}
            ).status_code
            == 202
        )
        assert outbox.process_one()
    assert sent == []
    with client.app.state.SessionLocal.begin() as db:
        user = db.scalar(select(User))
        user.email = "owner@example.com"
        user.email_verified = True
    assert (
        client.post(
            "/api/auth/password-reset-request", json={"email": "owner@example.com"}
        ).status_code
        == 202
    )
    for attempt in range(3):
        assert outbox.process_one()
        with client.app.state.SessionLocal.begin() as db:
            job = db.scalar(
                select(EmailJob).where(
                    EmailJob.kind == "reset", EmailJob.status != "discarded"
                )
            )
            assert job.attempts == attempt + 1
            if attempt < 2:
                assert "owner@example.com" not in job.payload
                job.next_attempt_at = utc_now()
            else:
                assert job.status == "sent" and job.payload is None
            assert db.scalar(select(func.count()).select_from(PasswordResetToken)) == 1
    assert sent[0] == sent[1] == sent[2]


def test_outbox_capacity_and_recipient_limits(secured):
    client, headers = secured
    settings = client.app.state.settings
    settings.email_outbox_limit = 1
    assert (
        client.post(
            "/api/auth/password-reset-request", json={"email": "missing@example.com"}
        ).status_code
        == 202
    )
    assert (
        client.post(
            "/api/auth/password-reset-request", json={"email": "other@example.com"}
        ).status_code
        == 503
    )
    settings.email_outbox_limit = 100
    settings.rate_limit_enabled = True
    for _ in range(3):
        assert (
            client.post(
                "/api/auth/password-reset-request",
                json={"email": "limited@example.com"},
            ).status_code
            == 202
        )
    assert (
        client.post(
            "/api/auth/password-reset-request", json={"email": "limited@example.com"}
        ).status_code
        == 429
    )


def test_device_rename_revoke_idempotent_and_audit_isolation(client, auth_headers):
    device = register_device(client, auth_headers)
    path = "/api/devices/" + device["device_id"]
    assert (
        client.patch(path, headers=auth_headers, json={"name": "   "}).status_code
        == 422
    )
    assert (
        client.patch(path, headers=auth_headers, json={"name": " Nuovo "}).json()[
            "device"
        ]["name"]
        == "Nuovo"
    )
    for _ in range(2):
        assert client.post(path + "/revoke", headers=auth_headers).status_code == 200
    with client.app.state.SessionLocal.begin() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.event_type == "device_revoked")
            )
            == 1
        )
        db.add(
            AuditLog(
                id="foreign",
                owner_id="foreign",
                event_type="login_failed",
                event_payload_json={"password": "never"},
            )
        )
        user = db.scalar(select(User))
        db.add(
            AuditLog(
                id="secret",
                owner_id=user.id,
                event_type="new_event",
                event_payload_json={"password": "never"},
            )
        )
    data = client.get("/api/activity?limit=1", headers=auth_headers).json()
    ids = []
    for _ in range(30):
        ids += [row["id"] for row in data["events"]]
        assert "never" not in json.dumps(data)
        if not data["next_cursor"]:
            break
        data = client.get(
            "/api/activity",
            headers=auth_headers,
            params={"limit": 1, "cursor": data["next_cursor"]},
        ).json()
    assert not data["next_cursor"], "Pagination must terminate"
    assert "foreign" not in ids and len(ids) == len(set(ids))
    assert (
        client.get("/api/activity/summary", headers=auth_headers).json()[
            "authentication_failures"
        ]
        == 0
    )
    assert (
        client.get(
            "/api/activity?start=2020-01-01&end=2026-01-01", headers=auth_headers
        ).status_code
        == 400
    )


def test_old_schema_rejected_without_ddl(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as db:
        db.execute(text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        db.execute(text("INSERT INTO users VALUES ('keep')"))
    with pytest.raises(RuntimeError, match="database nuovo"):
        init_db(engine)
    with engine.connect() as db:
        assert db.execute(text("SELECT id FROM users")).scalar() == "keep"
        assert (
            db.execute(
                text("SELECT count(*) FROM sqlite_master WHERE type='table'")
            ).scalar()
            == 1
        )
    engine.dispose()


def test_local_smtp_delivery_and_restart(secured):
    import asyncio
    import socketserver
    import threading
    from app.email_outbox import EmailOutbox, enqueue
    from app.metrics import Metrics

    client, _ = secured
    received = []

    class SMTP(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 localhost test\r\n")
            while line := self.rfile.readline():
                command = line.decode().split()[0].upper()
                if command == "DATA":
                    self.wfile.write(b"354 send data\r\n")
                    body = bytearray()
                    while (line := self.rfile.readline()) != b".\r\n":
                        if not line:
                            return
                        body.extend(line)
                    received.append(bytes(body))
                    self.wfile.write(b"250 accepted\r\n")
                elif command == "QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 OK\r\n")

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTP) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        settings = client.app.state.settings
        settings.smtp_host = "127.0.0.1"
        settings.smtp_port = server.server_address[1]
        with client.app.state.SessionLocal.begin() as db:
            job = enqueue(
                db,
                settings,
                "notification",
                {"email": "local@example.com", "body": "Messaggio di test locale"},
            )
            job.status = "sending"
        worker = EmailOutbox(client.app.state.SessionLocal, settings, Metrics())

        async def restart():
            await worker.start()
            await worker.close()

        asyncio.run(restart())
        worker.process_one()
        server.shutdown()
        thread.join()
    assert len(received) == 1 and b"Messaggio di test locale" in received[0]
    with client.app.state.SessionLocal() as db:
        job = db.scalar(select(EmailJob))
        assert job.status == "sent" and job.payload is None


def test_mfa_totp_window_and_concurrent_replay(secured, monkeypatch):
    import time

    client, headers = secured
    secret, _ = enable_mfa(client, headers)
    moment = time.time() + 120
    monkeypatch.setattr("app.account_service.time.time", lambda: moment)
    tokens = [challenge(client), challenge(client)]
    code = pyotp.TOTP(secret).at(moment - 30)

    def verify(token):
        with client.app.state.SessionLocal() as db:
            try:
                AccountService(db, client.app.state.settings).verify_challenge(
                    token, code, None, {}
                )
                db.commit()
                return True
            except AuthenticationError:
                db.commit()
                return False

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(verify, tokens)) == [False, True]
    token = challenge(client)
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).at(moment + 60)},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "code": pyotp.TOTP(secret).at(moment + 30)},
        ).status_code
        == 200
    )


def test_mfa_setup_session_bound_and_recovery_regeneration(secured):
    client, headers = secured
    setup = client.post(
        "/api/auth/mfa/setup", headers=headers, json={"password": PASSWORD}
    ).json()
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": PASSWORD}
    ).json()
    other = {"Authorization": "Bearer " + login["access_token"]}
    assert (
        client.post(
            "/api/auth/mfa/confirm",
            headers=other,
            json={"code": pyotp.TOTP(setup["secret"]).now()},
        ).status_code
        == 400
    )
    _, codes = enable_mfa(client, headers)
    login = client.post(
        "/api/auth/mfa/verify",
        json={"challenge_token": challenge(client), "recovery_code": codes[0]},
    ).json()
    headers = {"Authorization": "Bearer " + login["access_token"]}
    result = client.post(
        "/api/auth/mfa/recovery-codes/regenerate",
        headers=headers,
        json={"password": PASSWORD, "recovery_code": codes[1]},
    )
    assert result.status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/auth/refresh", json={"refresh_token": login["refresh_token"]}
        ).status_code
        == 401
    )
    token = challenge(client)
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={"challenge_token": token, "recovery_code": codes[2]},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/mfa/verify",
            json={
                "challenge_token": token,
                "recovery_code": result.json()["recovery_codes"][0],
            },
        ).status_code
        == 200
    )


def test_email_expiry_and_recipient_specific_limits(secured):
    from app.routes.account import recipient_limit
    from starlette.requests import Request
    from fastapi import HTTPException
    from app.models import EmailVerification

    client, headers = secured
    client.post(
        "/api/auth/email-change-request",
        headers=headers,
        json={"email": "pending@example.com", "password": PASSWORD},
    )
    token = verification_token(client)
    with client.app.state.SessionLocal.begin() as db:
        db.scalar(
            select(EmailVerification).where(
                EmailVerification.token_hash == hash_secret(token)
            )
        ).expires_at = utc_now() - timedelta(seconds=1)
    assert (
        client.post("/api/auth/email-verify", json={"token": token}).status_code == 400
    )
    client.app.state.settings.rate_limit_enabled = True
    request = Request({"type": "http", "app": client.app, "headers": []})
    for _ in range(3):
        recipient_limit(request, "unknown@example.com", "test-recipient")
    with pytest.raises(HTTPException) as error:
        recipient_limit(request, "unknown@example.com", "test-recipient")
    assert error.value.status_code == 429
    recipient_limit(request, "unknown@example.com", "test-verification", "owner")
    with pytest.raises(HTTPException):
        recipient_limit(request, "unknown@example.com", "test-verification", "owner")


@pytest.fixture
def email_clock(monkeypatch):
    import time
    from types import SimpleNamespace

    import limits.storage.memory
    import app.email_outbox

    start = utc_now()
    epoch = time.time()
    elapsed = [0]
    monkeypatch.setattr(
        limits.storage.memory, "time", SimpleNamespace(time=lambda: epoch + elapsed[0])
    )
    monkeypatch.setattr(
        app.email_outbox, "utc_now", lambda: start + timedelta(seconds=elapsed[0])
    )
    return elapsed


def test_verification_recipient_limits_shared_across_owners_and_endpoints(
    secured, email_clock
):
    client, admin_headers = secured
    owners = [admin_headers]
    for i in range(2):
        credentials = {"username": f"owner{i}", "password": PASSWORD}
        assert client.post("/api/auth/register", json=credentials).status_code == 200
        login = client.post("/api/auth/login", json=credentials).json()
        owners.append({"Authorization": "Bearer " + login["access_token"]})
    client.app.state.settings.rate_limit_enabled = True
    email = "shared@example.com"
    assert (
        client.post(
            "/api/auth/register",
            json={"username": "initial", "password": PASSWORD, "email": email},
        ).status_code
        == 200
    )
    # A different owner cannot bypass the recipient's initial 60-second cooldown.
    change = {"email": " SHARED@EXAMPLE.COM ", "password": PASSWORD}
    response = client.post(
        "/api/auth/email-change-request", headers=owners[0], json=change
    )
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    email_clock[0] += 61
    assert (
        client.post(
            "/api/auth/email-change-request", headers=owners[0], json=change
        ).status_code
        == 200
    )
    with client.app.state.SessionLocal.begin() as db:
        db.scalar(select(User).where(User.username == "owner0")).pending_email = email
    email_clock[0] += 61
    assert (
        client.post(
            "/api/auth/email-verification-request", headers=owners[1], json={}
        ).status_code
        == 200
    )
    email_clock[0] += 61
    assert (
        client.post(
            "/api/auth/email-change-request", headers=owners[2], json=change
        ).status_code
        == 429
    )
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EmailJob)) == 3
        assert (
            db.scalar(select(User).where(User.username == "owner1")).pending_email
            is None
        )


def test_verification_owner_budget_shared_by_change_and_resend(secured, email_clock):
    client, headers = secured
    client.app.state.settings.rate_limit_enabled = True
    for path, payload in [
        ("email-change-request", {"email": "one@example.com", "password": PASSWORD}),
        ("email-verification-request", {}),
        ("email-change-request", {"email": "two@example.com", "password": PASSWORD}),
    ]:
        response = client.post("/api/auth/" + path, headers=headers, json=payload)
        assert response.status_code == 200, response.text
        email_clock[0] += 61
    assert (
        client.post(
            "/api/auth/email-verification-request", headers=headers, json={}
        ).status_code
        == 429
    )
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EmailJob)) == 3


@pytest.fixture
def full_security_outbox(secured):
    from app.email_outbox import enqueue

    client, headers = secured
    client.app.state.settings.email_outbox_limit = 1
    with client.app.state.SessionLocal.begin() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.email = "verified@example.com"
        user.email_verified = True
        enqueue(db, client.app.state.settings, "reset", {"email": "queued@example.com"})
    return client, headers


def test_full_outbox_does_not_rollback_password_reset(full_security_outbox, caplog):
    client, headers = full_security_outbox
    token = create_reset_token(client, "admin")
    payload = {"token": token, "new_password": "Montagna!Gialla9Quercia"}
    response = client.post("/api/auth/password-reset", json=payload)
    assert response.status_code == 200, response.text
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert client.post("/api/auth/password-reset", json=payload).status_code == 400
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": payload["new_password"]},
        ).status_code
        == 200
    )
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EmailJob)) == 1
    assert "Security notification omitted" in caplog.text
    assert "verified@example.com" not in caplog.text


@pytest.mark.parametrize("action", ["confirm", "disable", "regenerate"])
def test_full_outbox_preserves_mfa_changes_and_session_revocation(
    full_security_outbox, action
):
    client, headers = full_security_outbox
    _, codes = enable_mfa(client, headers)
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    login = client.post(
        "/api/auth/mfa/verify",
        json={"challenge_token": challenge(client), "recovery_code": codes[0]},
    )
    assert login.status_code == 200, login.text
    if action != "confirm":
        tokens = login.json()
        headers = {"Authorization": "Bearer " + tokens["access_token"]}
        path = "disable" if action == "disable" else "recovery-codes/regenerate"
        response = client.post(
            "/api/auth/mfa/" + path,
            headers=headers,
            json={"password": PASSWORD, "recovery_code": codes[1]},
        )
        assert response.status_code == 200, response.text
        assert client.get("/api/auth/me", headers=headers).status_code == 401
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )
        if action == "disable":
            assert (
                client.post(
                    "/api/auth/login", json={"username": "admin", "password": PASSWORD}
                ).status_code
                == 200
            )
        else:
            token = challenge(client)
            assert (
                client.post(
                    "/api/auth/mfa/verify",
                    json={"challenge_token": token, "recovery_code": codes[2]},
                ).status_code
                == 401
            )
            assert (
                client.post(
                    "/api/auth/mfa/verify",
                    json={
                        "challenge_token": token,
                        "recovery_code": response.json()["recovery_codes"][0],
                    },
                ).status_code
                == 200
            )
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EmailJob)) == 1


def test_full_outbox_does_not_rollback_email_verification(secured):
    client, headers = secured
    client.app.state.settings.email_outbox_limit = 1
    assert (
        client.post(
            "/api/auth/email-change-request",
            headers=headers,
            json={"email": "new@example.com", "password": PASSWORD},
        ).status_code
        == 200
    )
    token = verification_token(client)
    response = client.post("/api/auth/email-verify", json={"token": token})
    assert response.status_code == 200, response.text
    assert client.get("/api/auth/me", headers=headers).json()["email_verified"]
    assert (
        client.post("/api/auth/email-verify", json={"token": token}).status_code == 400
    )
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EmailJob)) == 1


def test_three_device_sessions_limit_and_independent_close(
    client, auth_headers, owner_token
):
    from contextlib import ExitStack

    devices = [
        register_device(client, auth_headers, name=f"Device {i}") for i in range(4)
    ]
    with ExitStack() as stack:
        sockets = []
        for device in devices:
            ws = stack.enter_context(
                client.websocket_connect(
                    "/device/ws?device_id=" + device["device_id"],
                    headers={"Authorization": "Bearer " + device["device_token"]},
                )
            )
            assert ws.receive_json()["type"] == "device_registered"
            sockets.append(ws)
        console = stack.enter_context(
            client.websocket_connect(
                "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
            )
        )
        assert console.receive_json()["type"] == "console_registered"
        ids = []
        for device, ws in zip(devices[:3], sockets):
            request_session(console, device["device_id"], "password-device")
            ids.append(ws.receive_json()["sessionId"])
            assert console.receive_json()["sessionId"] == ids[-1]
        request_session(console, devices[3]["device_id"], "password-device")
        assert console.receive_json()["code"] == "SESSION_LIMIT"
        console.send_json(
            {"type": "session_end", "sessionId": ids[0], "reason": "user_closed"}
        )
        assert sockets[0].receive_json()["sessionId"] == ids[0]
        assert console.receive_json()["sessionId"] == ids[0]
        console.send_json(
            {"type": "input_global_action", "sessionId": ids[1], "action": "HOME"}
        )
        assert sockets[1].receive_json()["sessionId"] == ids[1]


def test_reset_worker_rechecks_email_under_user_lock(secured, monkeypatch):
    from app.auth_service import AuthService

    client, _ = secured
    with client.app.state.SessionLocal.begin() as db:
        user = db.scalar(select(User))
        user.email = "old@example.com"
        user.email_verified = True
    assert (
        client.post(
            "/api/auth/password-reset-request", json={"email": "old@example.com"}
        ).status_code
        == 202
    )
    original = AuthService._lock_user

    def changed(self, user_id):
        user = original(self, user_id)
        user.email = "new@example.com"
        return user

    monkeypatch.setattr(AuthService, "_lock_user", changed)
    delivered = []
    monkeypatch.setattr(
        client.app.state.email_outbox, "send", lambda *args: delivered.append(args)
    )
    assert client.app.state.email_outbox.process_one()
    assert not delivered
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(PasswordResetToken)) == 0
        assert db.scalar(select(EmailJob)).status == "discarded"


def test_other_owner_cannot_rename_or_read_activity(client, auth_headers):
    device = register_device(client, auth_headers)
    client.post("/api/auth/register", json={"username": "other", "password": PASSWORD})
    token = client.post(
        "/api/auth/login", json={"username": "other", "password": PASSWORD}
    ).json()["access_token"]
    other = {"Authorization": "Bearer " + token}
    assert (
        client.patch(
            "/api/devices/" + device["device_id"],
            headers=other,
            json={"name": "stolen"},
        ).status_code
        == 404
    )
    assert (
        client.get(
            "/api/activity", headers=other, params={"device_id": device["device_id"]}
        ).json()["events"]
        == []
    )
    summary = client.get("/api/activity/summary", headers=other).json()
    assert (
        summary["devices"]
        == summary["connected_devices"]
        == summary["active_sessions"]
        == 0
    )


def test_local_stop_audit_is_attributed_to_device_owner(client, auth_headers):
    device = register_device(client, auth_headers)
    with client.websocket_connect(
        "/device/ws?device_id=" + device["device_id"],
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as ws:
        ws.receive_json()
        ws.send_json({"type": "device_local_stop", "reason": "local_paused"})
        ws.send_json({"type": "heartbeat"})
        assert ws.receive_json()["type"] == "heartbeat_ack"
    result = client.get(
        "/api/activity",
        headers=auth_headers,
        params={"event_type": "device_local_stop"},
    ).json()["events"]
    assert len(result) == 1 and result[0]["device_id"] == device["device_id"]


def test_crash_after_third_smtp_attempt_does_not_reset_budget(secured):
    import asyncio
    from app.email_outbox import EmailOutbox, enqueue
    from app.metrics import Metrics

    client, _ = secured
    with client.app.state.SessionLocal.begin() as db:
        job = enqueue(
            db,
            client.app.state.settings,
            "notification",
            {"email": "test@example.com", "body": "test"},
        )
        job.status = "sending"
        job.attempts = 3
    worker = EmailOutbox(
        client.app.state.SessionLocal, client.app.state.settings, Metrics()
    )

    async def restart():
        await worker.start()
        await worker.close()

    asyncio.run(restart())
    assert not worker.process_one()
    with client.app.state.SessionLocal() as db:
        job = db.scalar(select(EmailJob))
        assert job.status == "failed" and job.payload is None
