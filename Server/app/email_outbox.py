"""Single-process durable email queue. SMTP never runs inside a DB transaction."""

import asyncio
import json
import logging
import secrets
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from fastapi import HTTPException
from prometheus_client import Counter, Gauge
from sqlalchemy import func, select, update

from app.account_service import decrypt, encrypt
from app.auth_service import AuthService
from app.models import (
    BootstrapLock,
    EmailJob,
    EmailVerification,
    PasswordResetToken,
    User,
)
from app.security import hash_secret
from app.timeutils import naive_utc, utc_now

logger = logging.getLogger(__name__)


class OutboxFull(HTTPException):
    def __init__(self):
        super().__init__(503, "Servizio email non disponibile")


def enqueue(db, settings, kind, payload):
    if not settings.email_available:
        raise HTTPException(503, "Servizio email non disponibile")
    # Serialize queue capacity checks; registration already uses this same singleton.
    db.execute(update(BootstrapLock).where(BootstrapLock.id == 1).values(id=1))
    count = db.scalar(
        select(func.count())
        .select_from(EmailJob)
        .where(EmailJob.status.in_(["pending", "sending"]))
    )
    if count >= settings.email_outbox_limit:
        raise OutboxFull()
    job = EmailJob(
        id=secrets.token_urlsafe(16),
        kind=kind,
        payload=encrypt(settings, json.dumps(payload)),
        next_attempt_at=utc_now(),
    )
    db.add(job)
    db.flush()
    return job


def notification(db, settings, email, text):
    if email and settings.email_available:
        try:
            enqueue(db, settings, "notification", {"email": email, "body": text})
        except OutboxFull:
            # Capacity is checked before insertion: the transaction remains usable.
            # Security changes must commit even when their advisory email cannot fit.
            logger.warning(
                "Security notification omitted: email outbox capacity reached"
            )


class EmailOutbox:
    def __init__(self, factory, settings, metrics):
        self.factory, self.settings = factory, settings
        self.stop_event = asyncio.Event()
        self.task = None
        self.attempts = Counter(
            "mydesk_email_attempts_total", "SMTP attempts", registry=metrics.registry
        )
        self.failures = Counter(
            "mydesk_email_failures_total", "SMTP failures", registry=metrics.registry
        )
        self.pending = Gauge(
            "mydesk_email_pending", "Pending email jobs", registry=metrics.registry
        )

    async def start(self):
        if not self.settings.email_available:
            return
        with self.factory.begin() as db:
            db.execute(
                update(EmailJob)
                .where(EmailJob.status == "sending", EmailJob.attempts < 3)
                .values(status="pending")
            )
            db.execute(
                update(EmailJob)
                .where(EmailJob.status == "sending", EmailJob.attempts >= 3)
                .values(status="failed", payload=None, token_hash=None)
            )
        self.stop_event.clear()
        self.task = asyncio.create_task(self.run())

    async def close(self):
        self.stop_event.set()
        if self.task:
            await self.task
            self.task = None

    async def run(self):
        while not self.stop_event.is_set():
            try:
                worked = await asyncio.to_thread(self.process_one)
            except Exception as error:
                logger.error(
                    "Email consumer failure", extra={"error_type": type(error).__name__}
                )
                worked = False
            if not worked:
                try:
                    await asyncio.wait_for(self.stop_event.wait(), 1)
                except TimeoutError:
                    pass

    def finish(self, job, status):
        job.status = status
        job.payload = None
        job.token_hash = None

    def process_one(self):
        with self.factory.begin() as db:
            self.pending.set(
                db.scalar(
                    select(func.count())
                    .select_from(EmailJob)
                    .where(EmailJob.status.in_(["pending", "sending"]))
                )
            )
            job = db.scalar(
                select(EmailJob)
                .where(
                    EmailJob.status == "pending", EmailJob.next_attempt_at <= utc_now()
                )
                .order_by(EmailJob.next_attempt_at, EmailJob.id)
                .limit(1)
            )
            if not job:
                return False
            payload = json.loads(decrypt(self.settings, job.payload))
            if job.kind == "reset" and not job.token_hash:
                user = db.scalar(
                    select(User).where(
                        User.email == payload["email"],
                        User.email_verified.is_(True),
                        User.is_active.is_(True),
                    )
                )
                if not user:
                    self.finish(job, "discarded")
                    return True
                service = AuthService(db, self.settings)
                user = service._lock_user(user.id)
                if (
                    not user.is_active
                    or not user.email_verified
                    or user.email != payload["email"]
                ):
                    self.finish(job, "discarded")
                    return True
                token = service.create_password_reset_token(user.id)
                job.token_hash = hash_secret(token)
                payload["body"] = (
                    f"Reimposta la password (30 minuti): {self.settings.public_base_url.rstrip('/')}/#reset={token}"
                )
                job.payload = encrypt(self.settings, json.dumps(payload))
                db.flush()
            if job.token_hash:
                model = PasswordResetToken if job.kind == "reset" else EmailVerification
                valid = db.scalar(
                    select(model).where(
                        model.token_hash == job.token_hash,
                        model.used_at.is_(None),
                        model.expires_at > utc_now(),
                    )
                )
                if not valid:
                    self.finish(job, "discarded")
                    return True
            job.status = "sending"
            # Count before SMTP, so a crash cannot reset the attempt budget.
            job.attempts += 1
            job.next_attempt_at = utc_now() + timedelta(
                seconds=60 if job.attempts == 1 else 300
            )
            job_id = job.id
        # Committed token/message survive crash and retries; no transaction during SMTP.
        success = False
        self.attempts.inc()
        try:
            self.send(payload["email"], payload["body"], job_id)
            success = True
        except Exception as error:
            self.failures.inc()
            logger.warning(
                "SMTP delivery failed", extra={"error_type": type(error).__name__}
            )
        with self.factory.begin() as db:
            job = db.get(EmailJob, job_id)
            if success or job.attempts >= 3:
                self.finish(job, "sent" if success else "failed")
            else:
                job.status = "pending"
                job.next_attempt_at = utc_now() + timedelta(
                    seconds=60 if job.attempts == 1 else 300
                )
        return True

    def send(self, recipient, body, job_id):
        settings = self.settings
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = recipient
        message["Subject"] = "MyDesk — sicurezza account"
        message["Message-ID"] = f"<{job_id}@mydesk.local>"
        message.set_content(body)
        context = ssl.create_default_context()
        connection = (
            smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=10, context=context
            )
            if settings.smtp_tls == "ssl"
            else smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
        )
        with connection as smtp:
            if settings.smtp_tls == "starttls":
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)


def queue_verification(db, settings, user):
    email = user.pending_email
    if not email:
        raise ValueError("Nessun indirizzo in attesa")
    previous_expiry = db.scalar(
        select(func.max(EmailVerification.expires_at)).where(
            EmailVerification.user_id == user.id
        )
    )
    if (
        settings.rate_limit_enabled
        and previous_expiry
        and naive_utc(previous_expiry) - timedelta(hours=24) + timedelta(seconds=60)
        > utc_now()
    ):
        raise HTTPException(
            429,
            "Attendi almeno 60 secondi prima del reinvio",
            headers={"Retry-After": "60"},
        )
    db.execute(
        update(EmailVerification)
        .where(EmailVerification.user_id == user.id)
        .values(used_at=utc_now())
    )
    token = secrets.token_urlsafe(32)
    digest = hash_secret(token)
    db.add(
        EmailVerification(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            email=email,
            token_hash=digest,
            expires_at=utc_now() + timedelta(hours=24),
        )
    )
    job = enqueue(
        db,
        settings,
        "verification",
        {
            "email": email,
            "body": f"Conferma l'indirizzo (24 ore): {settings.public_base_url.rstrip('/')}/#verify={token}",
        },
    )
    job.token_hash = digest
