"""Authentication endpoints — OIDC BFF login, sessions, and API tokens (spec 008 / ADR-0005).

The browser never receives an OIDC token: ``/login`` redirects to the IdP, ``/callback`` exchanges
the code server-side and sets a ``__Host-`` session cookie, and ``/me`` reports the identity.
Automation uses API tokens minted here. State-changing requests are CSRF-protected (see deps).
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..auth import service as auth_service
from ..auth import signing
from ..auth.oidc import OidcClient, make_pkce, provide_oidc_client
from ..deps import (
    CSRF_HEADER,
    SESSION_COOKIE,
    SESSION_COOKIE_DEV,
    current_user,
    get_session,
    session_cookie_value,
)
from ..models import ApiToken, User
from ..settings import Settings, get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_COOKIE = "khandaq_login"
LOGIN_TTL_SECONDS = 600


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


def _session_cookie_name(settings: Settings) -> str:
    return SESSION_COOKIE if settings.is_prod else SESSION_COOKIE_DEV


def _set_session_cookie(resp: Response, settings: Settings, sid: str) -> None:
    resp.set_cookie(
        _session_cookie_name(settings),
        sid,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.is_prod,
        samesite="lax",
        path="/",
    )


def _safe_next(raw: str | None) -> str:
    """Only allow same-origin relative paths, to block open-redirect via ``?next=``."""
    if raw and raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/"


@router.get("/login")
def login(
    next: str | None = Query(default=None),
    client: OidcClient = Depends(provide_oidc_client),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    cookie = signing.sign(
        {"state": state, "nonce": nonce, "verifier": verifier, "next": _safe_next(next)},
        secret=settings.session_secret,
        ttl_seconds=LOGIN_TTL_SECONDS,
    )
    url = client.authorization_url(state=state, nonce=nonce, code_challenge=challenge)
    resp = RedirectResponse(url, status_code=307)
    resp.set_cookie(
        LOGIN_COOKIE,
        cookie,
        max_age=LOGIN_TTL_SECONDS,
        httponly=True,
        secure=settings.is_prod,
        samesite="lax",
        path="/api/auth",
    )
    return resp


@router.get("/callback")
def callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    client: OidcClient = Depends(provide_oidc_client),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    raw = request.cookies.get(LOGIN_COOKIE)
    payload = signing.verify(raw, secret=settings.session_secret) if raw else None
    if payload is None or not secrets.compare_digest(payload.get("state", ""), state):
        raise HTTPException(400, "invalid or expired login state")

    token = client.exchange(code=code, code_verifier=payload["verifier"])
    id_token = token.get("id_token")
    if not id_token:
        raise HTTPException(400, "no id_token in token response")
    claims = client.claims(id_token=id_token, nonce=payload["nonce"])

    # Users are keyed by email, so the email must be one the IdP verified — otherwise anyone could
    # claim an existing account (or admin_email) by typing its address into an unverified profile.
    # Then only allow-listed addresses get in: the realm brokers ANY Google/GitHub account.
    email = str(claims.get("email", ""))
    reason = None
    if claims.get("email_verified") is not True:
        reason = "email not verified by the identity provider"
    elif not settings.email_allowed(email):
        reason = "not on KHANDAQ_ALLOWED_EMAILS"
    if reason is not None:
        return _deny_sign_in(session, email=email, reason=reason)

    user = auth_service.upsert_user_from_claims(
        session, admin_email=settings.admin_email or None, claims=claims
    )
    if user.disabled:
        return _deny_sign_in(session, email=email, reason="account disabled")
    row = auth_service.create_session(session, user, ttl_hours=settings.session_ttl_hours)
    session.flush()
    audit.record(session, action="auth.login", actor=user, detail={"session_id": row.id})
    session.commit()

    resp = RedirectResponse(_safe_next(payload.get("next")), status_code=307)
    _set_session_cookie(resp, settings, row.id)
    resp.delete_cookie(LOGIN_COOKIE, path="/api/auth")
    return resp


def _deny_sign_in(session: Session, *, email: str, reason: str) -> RedirectResponse:
    """No session; record the refusal and send the browser to the console's 'no access' notice."""
    session.rollback()  # drop anything flushed for this login (e.g. a just-created user row)
    audit.record(session, action="auth.denied", detail={"email": email, "reason": reason})
    session.commit()
    resp = RedirectResponse("/?signin=denied", status_code=307)
    resp.delete_cookie(LOGIN_COOKIE, path="/api/auth")
    return resp


@router.post("/logout")
def logout(
    request: Request,
    csrf: str | None = Header(default=None, alias=CSRF_HEADER),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_session),
) -> JSONResponse:
    sid = session_cookie_value(request, settings)
    if sid is not None:
        row = auth_service.lookup_session(session, sid)
        if row is not None:
            if csrf != row.csrf:
                raise HTTPException(403, "missing or invalid CSRF token")
            auth_service.revoke_session(session, sid)
            audit.record(
                session,
                action="auth.logout",
                actor=session.get(User, row.user_id),
                detail={"session_id": sid},
            )
            session.commit()
    resp = JSONResponse({"status": "logged_out"})
    resp.delete_cookie(_session_cookie_name(settings), path="/")
    return resp


@router.get("/me")
def me(
    request: Request,
    authorization: str | None = Header(default=None),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict:
    if authorization and authorization.lower().startswith("bearer "):
        method, csrf_token = "token", None
    else:
        sid = session_cookie_value(request, settings)
        row = auth_service.lookup_session(session, sid) if sid else None
        if row is not None:
            method, csrf_token = "session", row.csrf
        else:
            method, csrf_token = "dev", None
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "org_role": user.org_role,
        "csrf_token": csrf_token,
        "auth": method,
    }


@router.post("/tokens", status_code=201)
def create_token(
    body: TokenCreate,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> dict:
    row, plaintext = auth_service.create_api_token(session, user, name=body.name)
    session.flush()
    audit.record(session, action="token.create", actor=user, detail={"token_id": row.id})
    session.commit()
    return {"id": row.id, "name": row.name, "token": plaintext}


@router.get("/tokens")
def list_tokens(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[dict]:
    rows = session.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    ).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
            "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
        }
        for t in rows
    ]


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(
    token_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> Response:
    import datetime as dt

    row = session.get(ApiToken, token_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(404, "token not found")
    if row.revoked_at is None:
        row.revoked_at = dt.datetime.now(dt.UTC)
        audit.record(session, action="token.revoke", actor=user, detail={"token_id": row.id})
        session.commit()
    return Response(status_code=204)
