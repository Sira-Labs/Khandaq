"""Append-only audit log helper.

Every privileged action records an entry (ADR / spec 002, docs/architecture/04-...). The table is
append-only at the database (trigger from spec 001); this helper is the single place the app writes
to it, so the call sites stay uniform. The caller commits.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog, User


def record(
    session: Session,
    *,
    action: str,
    actor: User | None = None,
    engagement_id: str | None = None,
    detail: dict | None = None,
    token_id: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor.id if actor else None,
        actor_token_id=token_id,
        action=action,
        engagement_id=engagement_id,
        detail=detail or {},
    )
    session.add(entry)
    return entry
