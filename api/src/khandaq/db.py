"""Lightweight database access for the bootable skeleton.

The full persistence schema and migrations are spec 001; this module only reports the current
schema revision for GET /api/version, degrading gracefully when no database is configured or no
migrations have run yet. It never crashes the app on a database that is absent or not ready.
"""

from __future__ import annotations

import logging

from .settings import Settings

log = logging.getLogger("khandaq.db")


def schema_revision(settings: Settings) -> str:
    """Return the applied migration revision, or a sentinel when unavailable.

    "none" = no database configured; "unmigrated" = database reachable but no schema yet;
    "unknown" = database configured but not reachable right now (logged, not fatal).
    """
    if not settings.database_url:
        return "none"
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args={})
        try:
            with engine.connect() as conn:
                row = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).first()
                return row[0] if row else "unmigrated"
        finally:
            engine.dispose()
    except Exception as exc:  # noqa: BLE001 — version must never take the app down
        log.warning("schema_revision: database not reachable yet: %s", exc)
        return "unknown"
