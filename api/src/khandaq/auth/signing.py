"""Tamper-evident, short-lived signed payloads for the transient OIDC login cookie.

The login step must remember ``state``/``nonce``/PKCE ``verifier``/``next`` between the redirect to
the IdP and the callback, without a database round-trip. We keep them in a cookie signed with the
app ``session_secret`` (HMAC-SHA256), with an embedded expiry. This is *not* the login session —
that is a server-side row (``sessions``); this only protects the in-flight handshake.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def sign(payload: dict, *, secret: str, ttl_seconds: int) -> str:
    """Return ``<b64(json)>.<b64(hmac)>`` with an embedded expiry."""
    body = dict(payload, _exp=int(time.time()) + ttl_seconds)
    data = _b64e(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    return f"{data}.{_b64e(sig)}"


def verify(token: str, *, secret: str) -> dict | None:
    """Return the payload if the signature is valid and unexpired, else ``None``."""
    try:
        data, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    try:
        given = _b64d(sig)
    except ValueError:  # binascii.Error: a malformed cookie is a bad request, not a server error
        return None
    if not hmac.compare_digest(given, expected):
        return None
    try:
        payload = json.loads(_b64d(data))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or int(payload.get("_exp", 0)) < int(time.time()):
        return None
    payload.pop("_exp", None)
    return payload
