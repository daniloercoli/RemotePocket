"""Credential operations serialize on the user before consuming any token."""

import secrets
import time
from datetime import timedelta

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from email_validator import validate_email
from sqlalchemy import delete, select, update

from app.audit import write_audit
from app.auth_service import AuthService, AuthenticationError
from app.models import (
    EmailVerification,
    MfaChallenge,
    MfaSetup,
    RecoveryCode,
    PasswordResetToken,
    User,
)
from app.security import hash_secret, verify_password
from app.timeutils import naive_utc, utc_now


def normalize_email(value):
    return validate_email(
        value.strip(), check_deliverability=False
    ).normalized.casefold()


def cipher(settings):
    if not settings.encryption_key:
        raise AuthenticationError("Cifratura non configurata")
    return Fernet(settings.encryption_key.encode())


def encrypt(settings, value):
    return cipher(settings).encrypt(value.encode()).decode()


def decrypt(settings, value):
    try:
        return cipher(settings).decrypt(value.encode()).decode()
    except InvalidToken:
        raise AuthenticationError("Credenziali cifrate non disponibili") from None


class AccountService(AuthService):
    def revoke_credentials(self, user):
        self.session_manager.revoke_all_sessions(user.id)
        self.db.execute(
            update(MfaChallenge)
            .where(MfaChallenge.user_id == user.id)
            .values(used_at=utc_now())
        )
        self.db.execute(delete(MfaSetup).where(MfaSetup.user_id == user.id))

    def factor(self, user, code=None, recovery_code=None):
        if bool(code) == bool(recovery_code):
            raise AuthenticationError("Fornire un solo secondo fattore")
        if recovery_code:
            result = self.db.execute(
                update(RecoveryCode)
                .where(
                    RecoveryCode.user_id == user.id,
                    RecoveryCode.code_hash == hash_secret(recovery_code),
                    RecoveryCode.used_at.is_(None),
                )
                .values(used_at=utc_now())
            )
            if result.rowcount == 1:
                write_audit(self.db, "mfa_recovery_used", owner_id=user.id)
                return
        elif (
            code
            and code.isascii()
            and code.isdigit()
            and len(code) == 6
            and user.totp_secret
        ):
            totp = pyotp.TOTP(decrypt(self.settings, user.totp_secret))
            step = int(time.time()) // 30
            for accepted in (step, step - 1, step + 1):
                if accepted > user.totp_last_step and secrets.compare_digest(
                    totp.at(accepted * 30), code
                ):
                    user.totp_last_step = accepted
                    self.db.flush()
                    return
        raise AuthenticationError("Secondo fattore non valido o gia' utilizzato")

    def confirm_identity(self, user, password, code=None, recovery_code=None):
        user = self._lock_user(user.id)
        if not user.is_active or self._check_lockout(user):
            raise AuthenticationError("Account non disponibile")
        try:
            if not verify_password(password, user.password_hash):
                raise AuthenticationError("Credenziali non valide")
            if user.totp_secret:
                self.factor(user, code, recovery_code)
        except AuthenticationError:
            self._record_login_attempt(user, user.username, None, None, False)
            write_audit(self.db, "account_confirmation_failed", owner_id=user.id)
            raise
        return user

    def setup(self, user, session_id, password):
        user = (
            self.confirm_identity(user, password)
            if not user.totp_secret
            else self._lock_user(user.id)
        )
        if not self.session_manager.validate_session(session_id) or not user.is_active:
            raise AuthenticationError("Sessione non valida")
        if user.totp_secret:
            raise ValueError("TOTP gia' attiva")
        secret = pyotp.random_base32()
        self.db.merge(
            MfaSetup(
                user_id=user.id,
                session_id=session_id,
                secret=encrypt(self.settings, secret),
                expires_at=utc_now() + timedelta(minutes=10),
            )
        )
        return secret, pyotp.TOTP(secret).provisioning_uri(
            user.username, issuer_name="MyDesk"
        )

    def recovery_codes(self, user):
        self.db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
        codes = [secrets.token_hex(16) for _ in range(10)]
        for code in codes:
            self.db.add(
                RecoveryCode(
                    id=secrets.token_urlsafe(16),
                    user_id=user.id,
                    code_hash=hash_secret(code),
                )
            )
        return codes

    def confirm_setup(self, user, session_id, code):
        user = self._lock_user(user.id)
        if not self.session_manager.validate_session(session_id) or not user.is_active:
            raise AuthenticationError("Sessione non valida")
        setup = self.db.get(MfaSetup, user.id)
        if (
            user.totp_secret
            or not setup
            or setup.session_id != session_id
            or naive_utc(setup.expires_at) <= utc_now()
        ):
            raise ValueError("Configurazione TOTP scaduta o non valida")
        user.totp_secret = setup.secret
        try:
            self.factor(user, code)
        except AuthenticationError:
            user.totp_secret = None
            write_audit(self.db, "mfa_confirmation_failed", owner_id=user.id)
            raise
        codes = self.recovery_codes(user)
        from app.email_outbox import notification

        notification(
            self.db,
            self.settings,
            user.email if user.email_verified else None,
            "TOTP attivata per il tuo account MyDesk.",
        )
        self.revoke_credentials(user)
        write_audit(self.db, "mfa_enabled", owner_id=user.id)
        return codes

    def verify_challenge(self, token, code, recovery_code, info):
        challenge = self.db.scalar(
            select(MfaChallenge).where(MfaChallenge.token_hash == hash_secret(token))
        )
        if not challenge:
            raise AuthenticationError("Challenge non valida")
        user = self._lock_user(challenge.user_id)
        self.db.refresh(challenge)
        if (
            challenge.used_at
            or challenge.attempts >= 5
            or naive_utc(challenge.expires_at) <= utc_now()
            or not user.is_active
            or not user.totp_secret
            or self._check_lockout(user)
        ):
            write_audit(
                self.db,
                "mfa_failed",
                owner_id=user.id,
                payload={"reason": "challenge_invalid"},
            )
            raise AuthenticationError("Challenge scaduta o non valida")
        challenge.attempts += 1
        try:
            self.factor(user, code, recovery_code)
        except AuthenticationError:
            self._record_login_attempt(
                user,
                user.username,
                info.get("ip_address"),
                info.get("user_agent"),
                False,
            )
            write_audit(self.db, "mfa_failed", owner_id=user.id)
            raise
        challenge.used_at = utc_now()
        return self.complete_login(user, info)

    def verify_email(self, token):
        entry = self.db.scalar(
            select(EmailVerification).where(
                EmailVerification.token_hash == hash_secret(token)
            )
        )
        if not entry:
            raise ValueError("Verifica non valida")
        user = self._lock_user(entry.user_id)
        self.db.refresh(entry)
        if (
            not user.is_active
            or entry.used_at
            or naive_utc(entry.expires_at) <= utc_now()
            or user.pending_email != entry.email
        ):
            raise ValueError("Verifica scaduta o non valida")
        if self.db.scalar(
            select(User.id).where(User.email == entry.email, User.id != user.id)
        ):
            raise ValueError("Indirizzo non disponibile")
        old_email = user.email if user.email_verified else None
        entry.used_at = utc_now()
        user.email = entry.email
        user.email_verified = True
        user.pending_email = None
        self.db.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user.id)
            .values(used_at=utc_now())
        )
        write_audit(self.db, "email_verified", owner_id=user.id)
        return user, old_email
