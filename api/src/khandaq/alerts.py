"""Alerts on a worsened campaign diff (specs 017, 022): an outbox the worker delivers as a signed
webhook and, when configured, as an email. Each channel has its own row, retries and audit trail.

``queue_for_diff`` runs in the transaction that records the diff, so the alert exists exactly when
the diff does. ``deliver_due`` sends pending rows while holding their row lock (``SKIP LOCKED``), so
two workers never send one alert concurrently. It backs off exponentially and gives up after
``KHANDAQ_ALERT_MAX_ATTEMPTS``. Every outcome is audited. The payload names rules and counts, never
finding titles, evidence or target details.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import smtplib
import time
from email.message import EmailMessage
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import AlertOutbox, Campaign, CampaignDiff, Engagement, Run
from .settings import Settings, get_settings
from .smtp import SmtpSender, parse_smtp_url

log = logging.getLogger("khandaq.alerts")

PAYLOAD_SCHEMA = "khandaq.alert/1"
EVENT = "campaign.worsened"
WEBHOOK, EMAIL = "webhook", "email"
DELIVERY_BATCH = 10
TIMEOUT_SECONDS = 10.0  # hard wall-clock limit per delivery, connect to last byte
BATCH_BUDGET_SECONDS = 30.0  # no new delivery starts after this; the run loop must keep moving
MAX_BACKOFF_MINUTES = 60


class Sender(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """POST ``body``; return the HTTP status. Raise ``httpx.HTTPError`` or ``TimeoutError``
        on transport errors."""


class EmailSender(Protocol):
    def send(self, message: EmailMessage) -> None:
        """Hand ``message`` to the relay. Raise ``smtplib.SMTPException`` or ``OSError`` (including
        ``TimeoutError``) when it is not accepted."""


class HttpxSender:
    """The default sender: no redirects followed (a 3xx is a failed delivery, not a hop).

    httpx timeouts bound inactivity, not the whole exchange, so a receiver dribbling bytes could
    hold the worker (and every queued run behind it) for as long as it liked. The request runs
    under ``asyncio.wait_for``, a hard deadline that cancels it mid-stream (PR #34 review). The
    response body is never read: only the status matters."""

    def __init__(self, deadline_seconds: float = TIMEOUT_SECONDS) -> None:
        self.deadline_seconds = deadline_seconds

    async def _post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        async with httpx.AsyncClient(
            timeout=self.deadline_seconds, follow_redirects=False
        ) as client:
            async with client.stream("POST", url, content=body, headers=headers) as response:
                return response.status_code

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        return asyncio.run(
            asyncio.wait_for(self._post(url, body, headers), timeout=self.deadline_seconds)
        )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _brief(entries: list[dict]) -> list[dict]:
    return [{"rule_id": e["rule_id"], "severity": e["severity"]} for e in entries]


def enabled_channels(settings: Settings) -> list[str]:
    """The channels a deployment has configured (spec 022 §1)."""
    channels = []
    if settings.alert_webhook_url:
        channels.append(WEBHOOK)
    if settings.alert_email_recipients:
        channels.append(EMAIL)
    return channels


def queue_for_diff(session: Session, diff: CampaignDiff, run: Run) -> list[AlertOutbox]:
    """Queue one alert per enabled channel for a worsened diff (specs 017 §1, 022 §1). Caller
    commits."""
    settings = get_settings()
    channels = enabled_channels(settings)
    if not diff.worsened or not channels:
        return []
    session.flush()  # diff.id
    engagement = session.get(Engagement, run.engagement_id)
    campaign = session.get(Campaign, diff.campaign_id)
    if engagement is None or campaign is None:  # pragma: no cover - never deleted
        raise RuntimeError(f"diff {diff.id} lost its engagement or campaign")
    payload = {
        "schema": PAYLOAD_SCHEMA,
        "kind": EVENT,
        "engagement": {"id": engagement.id, "name": engagement.name},
        "campaign": {"id": campaign.id, "name": campaign.name},
        "run_id": run.id,
        "diff_id": diff.id,
        "counts": {
            "new": len(diff.new),
            "regressed": len(diff.regressed),
            "resolved": len(diff.resolved),
            "unchanged": diff.unchanged_count,
        },
        "new": _brief(diff.new),
        "regressed": _brief(diff.regressed),
        "url": f"{settings.public_url.rstrip('/')}/eng/{engagement.id}",
    }
    alerts = []
    for channel in channels:
        alert = AlertOutbox(
            engagement_id=engagement.id,
            campaign_id=campaign.id,
            diff_id=diff.id,
            channel=channel,
            payload=payload,
            state="pending",
            attempts=0,
            next_attempt_at=_now(),
        )
        session.add(alert)
        session.flush()
        audit.record(
            session,
            action="alert.queued",
            engagement_id=engagement.id,
            detail={
                "alert_id": alert.id,
                "channel": channel,
                "campaign_id": campaign.id,
                "diff_id": diff.id,
            },
        )
        alerts.append(alert)
    return alerts


def sign(secret: str, body: bytes) -> str:
    """The ``X-Khandaq-Signature`` value: ``sha256=`` + hex HMAC-SHA256 of the exact body."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _headers(alert: AlertOutbox, body: bytes, settings: Settings) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "X-Khandaq-Event": EVENT,
        "X-Khandaq-Delivery": alert.id,
    }
    if settings.alert_webhook_secret:
        headers["X-Khandaq-Signature"] = sign(settings.alert_webhook_secret, body)
    return headers


def _one_line(value: object) -> str:
    """User-chosen names reach a mail header: CR, LF and other whitespace runs become one space,
    so a name cannot inject a header (spec 022 §3)."""
    return " ".join(str(value).split())


def build_email(alert: AlertOutbox, settings: Settings) -> EmailMessage:
    """The plain-text email for an alert: the webhook payload's content, nothing more (spec 022)."""
    p = alert.payload
    counts = p["counts"]
    campaign = _one_line(p["campaign"]["name"])
    message = EmailMessage()
    message["Subject"] = (
        f"[Khandaq] {campaign} got worse: {counts['new']} new, {counts['regressed']} regressed"
    )
    message["From"] = settings.alert_email_from.strip()
    message["To"] = ", ".join(settings.alert_email_recipients)
    domain = settings.alert_email_from.strip().rsplit("@", 1)[-1]
    message["Message-ID"] = f"<{alert.id}@{domain}>"  # stable: a retry is recognisable
    lines = [
        f"Campaign {campaign} in engagement {_one_line(p['engagement']['name'])} got worse.",
        "",
        f"New: {counts['new']}  Regressed: {counts['regressed']}  "
        f"Resolved: {counts['resolved']}  Unchanged: {counts['unchanged']}",
    ]
    for label in ("new", "regressed"):
        if p.get(label):
            lines += ["", f"{label.capitalize()}:"]
            lines += [f"  {_one_line(e['rule_id'])} ({_one_line(e['severity'])})" for e in p[label]]
    lines += ["", f"Open the engagement: {p['url']}", "", "For authorised security testing only."]
    message.set_content("\n".join(lines) + "\n")
    return message


def _record_failure(session: Session, alert: AlertOutbox, error: str, settings: Settings) -> None:
    alert.attempts += 1
    alert.last_error = error[:200]
    if alert.attempts >= settings.alert_max_attempts:
        alert.state = "failed"
        audit.record(
            session,
            action="alert.failed",
            engagement_id=alert.engagement_id,
            detail={
                "alert_id": alert.id,
                "channel": alert.channel,
                "attempts": alert.attempts,
                "error": alert.last_error,
            },
        )
        log.error("alert delivery gave up", extra={"alert_id": alert.id, "error": error})
        return
    backoff = min(2**alert.attempts, MAX_BACKOFF_MINUTES)
    alert.next_attempt_at = _now() + dt.timedelta(minutes=backoff)
    log.warning(
        "alert delivery failed; retrying",
        extra={"alert_id": alert.id, "error": error, "in_minutes": backoff},
    )


def _deliver_webhook(alert: AlertOutbox, settings: Settings, sender: Sender) -> str | int:
    """POST the alert; the HTTP status on a response, or an error string on a transport error."""
    body = json.dumps(alert.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        return sender.post(settings.alert_webhook_url, body, _headers(alert, body, settings))
    except (httpx.HTTPError, TimeoutError) as exc:
        return type(exc).__name__


def _deliver_email(alert: AlertOutbox, settings: Settings, sender: EmailSender) -> str | None:
    """Send the alert by email; None when the relay accepted it, else an error string (an SMTP
    reply code or an exception class, never the relay's text)."""
    try:
        sender.send(build_email(alert, settings))
    except smtplib.SMTPResponseException as exc:
        return f"SMTP {exc.smtp_code}"
    except (smtplib.SMTPException, OSError) as exc:  # OSError covers TimeoutError and refusals
        return type(exc).__name__
    return None


def deliver_due(
    session: Session, sender: Sender | None = None, email_sender: EmailSender | None = None
) -> int:
    """Worker: deliver due pending alerts of the enabled channels (specs 017 §2, 022 §2). Returns
    how many were attempted."""
    settings = get_settings()
    channels = enabled_channels(settings)
    if not channels:
        session.rollback()
        return 0  # alerts off: pending rows wait, nothing is sent anywhere
    attempted = 0
    started = time.monotonic()
    for _ in range(DELIVERY_BATCH):
        if time.monotonic() - started > BATCH_BUDGET_SECONDS:
            session.rollback()
            break  # the rest wait for the next loop iteration, in the same order
        alert = session.scalars(
            select(AlertOutbox)
            .where(
                AlertOutbox.state == "pending",
                AlertOutbox.next_attempt_at <= _now(),
                AlertOutbox.channel.in_(channels),  # a channel turned off keeps its rows pending
            )
            .order_by(AlertOutbox.next_attempt_at, AlertOutbox.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        ).first()
        if alert is None:
            session.rollback()
            break
        attempted += 1
        error: str | None
        status: str | int
        if alert.channel == EMAIL:
            if email_sender is None:
                email_sender = SmtpSender(parse_smtp_url(settings.smtp_url), settings.smtp_password)
            error = _deliver_email(alert, settings, email_sender)
            status = "accepted"
        else:
            result = _deliver_webhook(alert, settings, sender or HttpxSender())
            ok = isinstance(result, int) and 200 <= result < 300
            error = None if ok else (result if isinstance(result, str) else f"HTTP {result}")
            status = result
        if error is None:
            alert.state = "sent"
            alert.sent_at = _now()
            alert.attempts += 1
            audit.record(
                session,
                action="alert.sent",
                engagement_id=alert.engagement_id,
                detail={"alert_id": alert.id, "channel": alert.channel, "status": status},
            )
        else:
            _record_failure(session, alert, error, settings)
        session.commit()  # each row's outcome on its own; releases its lock
    return attempted
