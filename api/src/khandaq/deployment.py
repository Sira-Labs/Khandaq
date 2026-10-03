"""What a process is configured with, without its secrets (spec 023).

``settings_summary`` is the only place that turns settings into something shown to an operator:
secrets, URLs and addresses become booleans or counts, so nothing confidential can leak through it.
Workers record their summary as a heartbeat; ``GET /api/deployment`` shows the API's own summary
next to every worker's, so a missing alert setting or a dead worker is visible after a redeploy.
"""

from __future__ import annotations

import datetime as dt
import os
import socket

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from . import __version__
from .evidence_store import parse_store_url
from .mapping_overlay import table_in_effect
from .models import WorkerHeartbeat
from .settings import Settings

ALIVE_WITHIN = dt.timedelta(minutes=2)
LISTED_WITHIN = dt.timedelta(hours=24)
PRUNE_AFTER = dt.timedelta(days=7)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def settings_summary(settings: Settings) -> dict:
    """The non-secret shape of a process's configuration."""
    try:
        store = parse_store_url(settings.object_store_url)
        store_kind = "s3" if store else "local"
    except ValueError:  # prod refuses it at startup; elsewhere the summary must still build
        store, store_kind = None, "invalid"
    retired = [k for k in settings.evidence_previous_keys.split(",") if k.strip()]
    table = table_in_effect()
    return {
        "role": settings.role,
        "env": settings.env,
        "evidence": {
            "key": bool(settings.evidence_key),
            "retired_keys": len(retired),
            "store": store_kind,
            "bucket": store[0] if store else None,
        },
        "alerts": {
            "webhook": bool(settings.alert_webhook_url),
            "email": bool(settings.alert_email_recipients),
        },
        "campaign_min_interval_minutes": settings.campaign_min_interval_minutes,
        "mappings": {"versions": table["versions"], "overlay": table["overlay"]},
        "adapter_runtime": settings.adapter_runtime,
    }


def worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def beat(session: Session, settings: Settings, *, wid: str, started_at: dt.datetime) -> None:
    """Upsert this worker's heartbeat. Commits."""
    now = _now()
    values = {
        "id": wid,
        "started_at": started_at,
        "seen_at": now,
        "app_version": __version__,
        "summary": settings_summary(settings),
    }
    stmt = insert(WorkerHeartbeat).values(**values)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[WorkerHeartbeat.id],
            set_={  # a restart can reuse the id (same hostname, PID 1): it is a new process
                "started_at": started_at,
                "seen_at": now,
                "app_version": __version__,
                "summary": values["summary"],
            },
        )
    )
    session.commit()


def prune(session: Session) -> int:
    """Delete heartbeats not seen for a week (restarts get new ids). Commits."""
    result = session.execute(
        delete(WorkerHeartbeat).where(WorkerHeartbeat.seen_at < _now() - PRUNE_AFTER)
    )
    session.commit()
    return int(getattr(result, "rowcount", 0) or 0)


def workers(session: Session) -> list[dict]:
    """Heartbeats seen in the last day, newest first, with ``alive`` computed now."""
    now = _now()
    rows = session.scalars(
        select(WorkerHeartbeat)
        .where(WorkerHeartbeat.seen_at >= now - LISTED_WITHIN)
        .order_by(WorkerHeartbeat.seen_at.desc())
    )
    return [
        {
            "id": r.id,
            "started_at": r.started_at,
            "seen_at": r.seen_at,
            "alive": r.seen_at >= now - ALIVE_WITHIN,
            "app_version": r.app_version,
            "summary": r.summary,
        }
        for r in rows
    ]
