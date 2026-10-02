"""Shared FastAPI dependencies: database session, current user, engagement access.

Authentication resolves in this order (spec 008 / ADR-0005):

1. ``Authorization: Bearer <token>`` → an API token (sha256 lookup), for CLI/CI automation.
2. The ``__Host-khandaq_session`` cookie → a live server-side session (the browser BFF). Unsafe
   methods additionally require the ``X-Khandaq-CSRF`` header to match the session's token.
3. The ``X-Khandaq-Dev-User`` development stub — **non-prod only**, so the local demo and the authz
   tests keep working. In prod this path is absent, so an unauthenticated request gets ``401``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Path, Request
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .auth import service as auth_service
from .models import Engagement, EngagementMember, User
from .settings import Settings, get_settings

DEV_USER_HEADER = "X-Khandaq-Dev-User"
CSRF_HEADER = "X-Khandaq-CSRF"
SESSION_COOKIE = "__Host-khandaq_session"  # prod: Secure + https + Path=/ + no Domain
SESSION_COOKIE_DEV = "khandaq_session"  # dev/test over http can't carry a __Host- cookie
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@lru_cache
def _engine_for(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, future=True)


def get_engine() -> Engine:
    s = get_settings()
    if not s.database_url:
        raise HTTPException(503, "database not configured (KHANDAQ_DATABASE_URL)")
    return _engine_for(s.database_url)


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise


def session_cookie_value(request: Request, settings: Settings) -> str | None:
    # Prod accepts only the __Host- cookie: it cannot be set by a sibling subdomain or over plain
    # http, which is what stops an attacker planting their own session id (login fixation).
    if settings.is_prod:
        return request.cookies.get(SESSION_COOKIE)
    return request.cookies.get(SESSION_COOKIE) or request.cookies.get(SESSION_COOKIE_DEV)


def _require_allowed(settings: Settings, user: User) -> None:
    """Refuse accounts not on the allow-list; checked per request, so removal is immediate."""
    if not settings.email_allowed(user.email):
        raise HTTPException(403, "no access: this account is not on KHANDAQ_ALLOWED_EMAILS")


def _bearer_token(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    dev_user: str | None = Header(default=None, alias=DEV_USER_HEADER),
    session: Session = Depends(get_session),
) -> User:
    settings = get_settings()

    # 1. API token (automation).
    token = _bearer_token(authorization)
    if token is not None:
        resolved = auth_service.verify_api_token(session, token)
        if resolved is None:
            raise HTTPException(401, "invalid or revoked API token")
        user, token_id = resolved
        _require_allowed(settings, user)
        session.commit()  # persist last_used_at even when the request itself writes nothing
        user.auth_token_id = token_id  # audit.record attributes this request's actions to the token
        return user

    # 2. Server-side session (browser BFF) with CSRF on unsafe methods.
    sid = session_cookie_value(request, settings)
    if sid is not None:
        row = auth_service.lookup_session(session, sid)
        if row is None:
            raise HTTPException(401, "session expired or invalid")
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != row.csrf:
            raise HTTPException(403, "missing or invalid CSRF token")
        session_user = session.get(User, row.user_id)
        if session_user is None or session_user.disabled:
            raise HTTPException(401, "session user is not available")
        _require_allowed(settings, session_user)
        return session_user

    # 3. Development stub — never in prod.
    if settings.is_prod:
        raise HTTPException(401, "authentication required")
    email = dev_user or settings.admin_email or "dev@khandaq.local"
    dev_user_obj = session.scalar(select(User).where(User.email == email))
    if dev_user_obj is None:
        is_admin = email == (settings.admin_email or "dev@khandaq.local")
        dev_user_obj = User(email=email, org_role="admin" if is_admin else "member")
        session.add(dev_user_obj)
        session.commit()
        session.refresh(dev_user_obj)
    return dev_user_obj


@dataclass
class EngagementAccess:
    engagement: Engagement
    user: User
    role: str  # the caller's effective engagement role ('owner' for org admins)
    session: Session


def require_engagement_role(*allowed: str):
    """Dependency factory: load the engagement and enforce the caller's engagement role.

    Org admins are treated as 'owner'. A user with no membership is refused (403). Passing no roles
    requires only membership (any role).
    """

    def dependency(
        engagement_id: str = Path(...),
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ) -> EngagementAccess:
        engagement = session.get(Engagement, engagement_id)
        if engagement is None:
            raise HTTPException(404, "engagement not found")
        if user.org_role == "admin":
            role = "owner"
        else:
            member = session.get(EngagementMember, (engagement_id, user.id))
            if member is None:
                raise HTTPException(403, "no access to this engagement")
            role = member.role
            if user.org_role == "read_only":
                # The org-level read-only role caps every engagement role: such a user may read
                # what they are a member of, never launch runs or change scope.
                role = "viewer"
        if allowed and role not in allowed:
            raise HTTPException(403, f"requires one of: {', '.join(allowed)}")
        return EngagementAccess(engagement=engagement, user=user, role=role, session=session)

    return dependency
