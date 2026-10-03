"""Alerts on a worsened campaign diff (spec 017): an outbox the worker delivers as signed webhooks.

``queue_for_diff`` runs in the transaction that records the diff, so the alert exists exactly when
the diff does. ``deliver_due`` sends pending rows while holding their row lock (``SKIP LOCKED``), so
two workers never send one alert concurrently. It backs off exponentially and gives up after
``KHANDAQ_ALERT_MAX_ATTEMPTS``. Every outcome is audited. The payload names rules and counts, never
finding titles, evidence or target details.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import AlertOutbox, Campaign, CampaignDiff, Engagement, Run
from .settings import Settings, get_settings

log = logging.getLogger("khandaq.alerts")

PAYLOAD_SCHEMA = "khandaq.alert/1"
EVENT = "campaign.worsened"
DELIVERY_BATCH = 10
TIMEOUT_SECONDS = 10.0
MAX_BACKOFF_MINUTES = 60


class Sender(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """POST ``body``; return the HTTP status. Raise ``httpx.HTTPError`` on transport errors."""


class HttpxSender:
    """The default sender: no redirects followed (a 3xx is a failed delivery, not a hop)."""

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        response = httpx.post(
            url, content=body, headers=headers, timeout=TIMEOUT_SECONDS, follow_redirects=False
        )
        return response.status_code


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _brief(entries: list[dict]) -> list[dict]:
    return [{"rule_id": e["rule_id"], "severity": e["severity"]} for e in entries]


def queue_for_diff(session: Session, diff: CampaignDiff, run: Run) -> AlertOutbox | None:
    """Queue an alert for a worsened diff when alerts are on (spec 017 §1). Caller commits."""
    settings = get_settings()
    if not diff.worsened or not settings.alert_webhook_url:
        return None
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
    alert = AlertOutbox(
        engagement_id=engagement.id,
        campaign_id=campaign.id,
        diff_id=diff.id,
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
        detail={"alert_id": alert.id, "campaign_id": campaign.id, "diff_id": diff.id},
    )
    return alert


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


def _record_failure(session: Session, alert: AlertOutbox, error: str, settings: Settings) -> None:
    alert.attempts += 1
    alert.last_error = error[:200]
    if alert.attempts >= settings.alert_max_attempts:
        alert.state = "failed"
        audit.record(
            session,
            action="alert.failed",
            engagement_id=alert.engagement_id,
            detail={"alert_id": alert.id, "attempts": alert.attempts, "error": alert.last_error},
        )
        log.error("alert delivery gave up", extra={"alert_id": alert.id, "error": error})
        return
    backoff = min(2**alert.attempts, MAX_BACKOFF_MINUTES)
    alert.next_attempt_at = _now() + dt.timedelta(minutes=backoff)
    log.warning(
        "alert delivery failed; retrying",
        extra={"alert_id": alert.id, "error": error, "in_minutes": backoff},
    )


def deliver_due(session: Session, sender: Sender | None = None) -> int:
    """Worker: deliver due pending alerts (spec 017 §2). Returns how many were attempted."""
    settings = get_settings()
    if not settings.alert_webhook_url:
        session.rollback()
        return 0  # alerts off: pending rows wait, nothing is sent anywhere
    sender = sender or HttpxSender()
    attempted = 0
    for _ in range(DELIVERY_BATCH):
        alert = session.scalars(
            select(AlertOutbox)
            .where(AlertOutbox.state == "pending", AlertOutbox.next_attempt_at <= _now())
            .order_by(AlertOutbox.next_attempt_at, AlertOutbox.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        ).first()
        if alert is None:
            session.rollback()
            break
        attempted += 1
        body = json.dumps(alert.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            status = sender.post(settings.alert_webhook_url, body, _headers(alert, body, settings))
        except httpx.HTTPError as exc:
            _record_failure(session, alert, type(exc).__name__, settings)
        else:
            if 200 <= status < 300:
                alert.state = "sent"
                alert.sent_at = _now()
                alert.attempts += 1
                audit.record(
                    session,
                    action="alert.sent",
                    engagement_id=alert.engagement_id,
                    detail={"alert_id": alert.id, "status": status},
                )
            else:
                _record_failure(session, alert, f"HTTP {status}", settings)
        session.commit()  # each row's outcome on its own; releases its lock
    return attempted
