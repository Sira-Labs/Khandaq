"""Session and API-token persistence for the BFF (spec 008 / ADR-0005).

Server-side sessions back the ``__Host-khandaq_session`` cookie; API tokens authenticate automation.
Tokens are stored only as a sha256 hash — the plaintext is shown once at creation and never again.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import ApiToken, User, UserSession

TOKEN_PREFIX = "kqt_"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# --- login sessions ---------------------------------------------------------------------------


def create_session(session: Session, user: User, *, ttl_hours: int) -> UserSession:
    row = UserSession(
        user_id=user.id,
        csrf=secrets.token_urlsafe(32),
        expires_at=_now() + dt.timedelta(hours=ttl_hours),
    )
    session.add(row)
    return row


def lookup_session(session: Session, session_id: str) -> UserSession | None:
    row = session.get(UserSession, session_id)
    if row is None or row.revoked_at is not None:
        return None
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.UTC)
    if expires < _now():
        return None
    return row


def revoke_session(session: Session, session_id: str) -> None:
    row = session.get(UserSession, session_id)
    if row is not None and row.revoked_at is None:
        row.revoked_at = _now()


# --- API tokens -------------------------------------------------------------------------------


def create_api_token(session: Session, user: User, *, name: str) -> tuple[ApiToken, str]:
    """Create a token, returning the row and the one-time plaintext secret."""
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(user_id=user.id, name=name, hash=hash_token(plaintext))
    session.add(row)
    return row, plaintext


def verify_api_token(session: Session, plaintext: str) -> tuple[User, str] | None:
    """Return ``(user, token_id)`` for a valid, unrevoked token, else ``None``."""
    row = session.scalar(select(ApiToken).where(ApiToken.hash == hash_token(plaintext)))
    if row is None or row.revoked_at is not None:
        return None
    user = session.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    row.last_used_at = _now()
    return user, row.id


# --- user upsert from OIDC claims -------------------------------------------------------------


class IdentityConflict(Exception):
    """The sign-in names an email that belongs to a different identity-provider account."""


def upsert_user_from_claims(session: Session, *, admin_email: str | None, claims: dict) -> User:
    """Find or create the user for verified OIDC claims, keyed by (``iss``, ``sub``).

    - A known (iss, sub) is that user, whatever its email says now; a changed (verified) email is
      followed, unless another user already has it.
    - A user from before identity keying (no iss/sub yet) is linked by email on its next sign-in.
    - An email already linked to a *different* (iss, sub) is refused, never merged: a second IdP
      account that verified the same address must not inherit the first one's engagements.

    Raises IdentityConflict for the refusals; the caller denies the sign-in and audits it.
    """
    issuer, subject, email = str(claims["iss"]), str(claims["sub"]), str(claims["email"])
    name = claims.get("name") or claims.get("preferred_username")

    user = session.scalar(
        select(User).where(User.oidc_issuer == issuer, User.oidc_subject == subject)
    )
    if user is not None:
        if user.email != email:
            holder = session.scalar(select(User).where(User.email == email))
            if holder is not None:
                raise IdentityConflict("the new email belongs to another account")
            audit.record(
                session,
                action="user.email_changed",
                actor=user,
                detail={"from": user.email, "to": email},
            )
            user.email = email
        if user.display_name is None:
            user.display_name = name
        return user

    user = session.scalar(select(User).where(User.email == email))
    if user is not None:
        if user.oidc_subject is not None:
            raise IdentityConflict("email is linked to another identity-provider account")
        user.oidc_issuer, user.oidc_subject = issuer, subject
        audit.record(
            session,
            action="user.identity_linked",
            actor=user,
            detail={"oidc_issuer": issuer, "oidc_subject": subject},
        )
        if user.display_name is None:
            user.display_name = name
        session.flush()
        return user

    is_admin = bool(admin_email) and email == admin_email
    user = User(
        email=email,
        oidc_issuer=issuer,
        oidc_subject=subject,
        display_name=name,
        org_role="admin" if is_admin else "member",
    )
    session.add(user)
    session.flush()
    return user
