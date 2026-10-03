"""OIDC Authorization-Code + PKCE client (ADR-0005).

The control plane never puts tokens in the browser: this client runs the server side of the
handshake — build the authorization URL, exchange the code at the token endpoint, and validate the
``id_token`` against the issuer's JWKS. It is a small ``Protocol`` so tests inject a fake and the
full callback path runs without a live Keycloak (the real client is exercised in deployment).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Protocol
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException

from ..settings import Settings, get_settings

log = logging.getLogger("khandaq.auth")


class IdentityProviderUnavailable(Exception):
    """The identity provider could not be reached or answered nonsense (discovery, token
    endpoint or JWKS). The message is safe to show; the cause is in the log."""


def make_pkce() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class OidcClient(Protocol):
    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str: ...

    def exchange(self, *, code: str, code_verifier: str) -> dict: ...

    def claims(self, *, id_token: str, nonce: str) -> dict: ...

    def end_session_url(self) -> str | None: ...


class KeycloakOidcClient:
    """Standard OIDC client driven by the issuer's discovery document.

    Works with Keycloak and any spec-compliant provider. Network calls go through httpx; discovery
    and JWKS are fetched lazily and cached for the process lifetime.
    """

    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._meta: dict | None = None
        self._jwks: jwt.PyJWKClient | None = None

    @property
    def redirect_uri(self) -> str:
        return self._s.public_url.rstrip("/") + "/api/auth/callback"

    def _metadata(self) -> dict:
        if self._meta is None:
            url = self._s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            try:
                resp = httpx.get(url, timeout=10.0)
                resp.raise_for_status()
                meta = resp.json()
                for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                    if not isinstance(meta.get(key), str):
                        raise ValueError(f"discovery document has no {key}")
            except (httpx.HTTPError, ValueError) as exc:
                # A wrong or unresolvable KHANDAQ_OIDC_ISSUER, a missing realm, or an IdP that is
                # down: say which in the log, and fail the sign-in clearly instead of with a 500.
                log.error(
                    "OIDC discovery failed",
                    extra={"discovery_url": url, "error": f"{type(exc).__name__}: {exc}"},
                )
                raise IdentityProviderUnavailable(
                    "the identity provider cannot be reached; check KHANDAQ_OIDC_ISSUER"
                ) from None
            self._meta = meta
        return self._meta

    def _jwks_client(self) -> jwt.PyJWKClient:
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self._metadata()["jwks_uri"])
        return self._jwks

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self._s.oidc_client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self._metadata()['authorization_endpoint']}?{urlencode(params)}"

    def exchange(self, *, code: str, code_verifier: str) -> dict:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self._s.oidc_client_id,
            "client_secret": self._s.oidc_client_secret,
            "code_verifier": code_verifier,
        }
        try:
            resp = httpx.post(self._metadata()["token_endpoint"], data=data, timeout=10.0)
        except httpx.HTTPError as exc:
            log.error("OIDC token exchange failed", extra={"error": type(exc).__name__})
            raise IdentityProviderUnavailable(
                "the identity provider's token endpoint cannot be reached"
            ) from None
        if resp.status_code != 200:
            raise HTTPException(400, "token exchange failed")
        return resp.json()

    def claims(self, *, id_token: str, nonce: str) -> dict:
        try:
            signing_key = self._jwks_client().get_signing_key_from_jwt(id_token)
        except jwt.PyJWKClientConnectionError as exc:
            log.error("OIDC signing keys unavailable", extra={"error": str(exc)})
            raise IdentityProviderUnavailable(
                "the identity provider's signing keys cannot be fetched"
            ) from None
        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256", "RS384", "RS512"],
                audience=self._s.oidc_client_id,
                issuer=self._metadata().get("issuer", self._s.oidc_issuer),
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(400, "invalid id_token") from exc
        if claims.get("nonce") != nonce:
            raise HTTPException(400, "nonce mismatch")
        if not claims.get("email"):
            raise HTTPException(400, "id_token has no email claim")
        return claims

    def end_session_url(self) -> str | None:
        try:
            return self._metadata().get("end_session_endpoint")
        except Exception:  # discovery unavailable — logout still clears the local session
            return None


def get_oidc_client(settings: Settings) -> OidcClient:
    """FastAPI dependency seam: the real client, or a 503 when OIDC is not configured.

    Overridden in tests with a fake. Kept module-level (not a class) so ``app.dependency_overrides``
    can target it.
    """
    if not settings.oidc_configured:
        raise HTTPException(
            503, "OIDC is not configured (KHANDAQ_OIDC_ISSUER / _CLIENT_SECRET / PUBLIC_URL)"
        )
    # One client per configuration, so discovery and the JWKS are fetched once per process rather
    # than on every login and callback.
    key = (
        settings.oidc_issuer,
        settings.oidc_client_id,
        settings.oidc_client_secret,
        settings.public_url,
    )
    cached = _CLIENTS.get(key)
    if cached is None:
        cached = _CLIENTS[key] = KeycloakOidcClient(settings)
    return cached


_CLIENTS: dict[tuple[str, str, str, str], KeycloakOidcClient] = {}


def provide_oidc_client() -> OidcClient:
    """FastAPI dependency: tests override this in ``app.dependency_overrides`` with a fake."""
    return get_oidc_client(get_settings())
