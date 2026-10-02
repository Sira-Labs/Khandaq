"""Append-only audit log helper.

Every privileged action records an entry (ADR / spec 002, docs/architecture/04-...). The table is
append-only at the database (trigger from spec 001); this helper is the single place the app writes
to it, so the call sites stay uniform. The caller commits.
"""

from __future__ import annotations

import contextvars

from sqlalchemy.orm import Session

from .models import AuditLog, User

# The API-token id for the current request, set by deps.current_user when a Bearer token
# authenticates. record() falls back to it so token-authenticated privileged actions are attributed
# to the token without every call site threading it through (spec 008 / ADR-0005).
_actor_token_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "khandaq_actor_token_id", default=None
)


def set_actor_token_id(token_id: str | None) -> None:
    _actor_token_id.set(token_id)


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
        actor_token_id=token_id if token_id is not None else _actor_token_id.get(),
        action=action,
        engagement_id=engagement_id,
        detail=detail or {},
    )
    session.add(entry)
    return entry
