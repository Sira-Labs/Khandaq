"""Shared FastAPI dependencies: database session, current user, engagement access.

Authentication here is a **development stub** — real OIDC is spec 008. In production the stub
refuses to authenticate (returns 501) rather than silently trusting a header, so a prod deployment
cannot be used until real auth lands. In dev/test the identity is the admin, or the
``X-Khandaq-Dev-User`` header, so authz can be exercised.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Path
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import Engagement, EngagementMember, User
from .settings import Settings, get_settings

DEV_USER_HEADER = "X-Khandaq-Dev-User"


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


def _resolve_identity(settings: Settings, dev_user: str | None) -> str:
    if settings.is_prod:
        # The dev stub never authenticates in prod; real auth is spec 008.
        raise HTTPException(501, "authentication is not configured yet (pending OIDC, spec 008)")
    return dev_user or settings.admin_email or "dev@khandaq.local"


def current_user(
    dev_user: str | None = Header(default=None, alias=DEV_USER_HEADER),
    session: Session = Depends(get_session),
) -> User:
    settings = get_settings()
    email = _resolve_identity(settings, dev_user)
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        is_admin = email == (settings.admin_email or "dev@khandaq.local")
        user = User(email=email, org_role="admin" if is_admin else "member")
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


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
        if allowed and role not in allowed:
            raise HTTPException(403, f"requires one of: {', '.join(allowed)}")
        return EngagementAccess(engagement=engagement, user=user, role=role, session=session)

    return dependency
