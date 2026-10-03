"""The real OIDC client fails clearly when the identity provider is unreachable or wrong."""

from __future__ import annotations

import httpx
import pytest

from khandaq.auth.oidc import IdentityProviderUnavailable, KeycloakOidcClient
from khandaq.settings import Settings


def _client(issuer: str) -> KeycloakOidcClient:
    return KeycloakOidcClient(
        Settings(oidc_issuer=issuer, oidc_client_secret="s", public_url="https://khandaq.test")
    )


def test_an_unresolvable_issuer_is_reported_not_raised_raw(monkeypatch, caplog):
    def no_dns(url, timeout):
        raise httpx.ConnectError("[Errno -5] No address associated with hostname")

    monkeypatch.setattr(httpx, "get", no_dns)
    with pytest.raises(IdentityProviderUnavailable, match="KHANDAQ_OIDC_ISSUER"):
        _client("https://keycloak.khandaq.invalid/realms/khandaq").authorization_url(
            state="s", nonce="n", code_challenge="c"
        )
    assert "OIDC discovery failed" in caplog.text


ENDPOINTS = {
    "authorization_endpoint": "https://idp.test/auth",
    "token_endpoint": "https://idp.test/token",
    "jwks_uri": "https://idp.test/certs",
}


def _discovery(monkeypatch, document) -> None:
    request = httpx.Request("GET", "https://idp.test/realms/x/.well-known/openid-configuration")
    monkeypatch.setattr(
        httpx, "get", lambda url, timeout: httpx.Response(200, json=document, request=request)
    )


@pytest.mark.parametrize(
    "document",
    [
        {"issuer": "x"},
        None,
        [],
        "not an object",
        {**ENDPOINTS, "authorization_endpoint": ""},
        {**ENDPOINTS, "jwks_uri": "  "},
    ],
)
def test_a_malformed_discovery_document_is_rejected(monkeypatch, document):
    _discovery(monkeypatch, document)
    with pytest.raises(IdentityProviderUnavailable):
        _client("https://idp.test/realms/x").authorization_url(
            state="s", nonce="n", code_challenge="c"
        )


def test_a_missing_realm_is_reported(monkeypatch):
    request = httpx.Request("GET", "https://idp.test/realms/nope/.well-known/openid-configuration")
    monkeypatch.setattr(httpx, "get", lambda url, timeout: httpx.Response(404, request=request))
    with pytest.raises(IdentityProviderUnavailable):
        _client("https://idp.test/realms/nope").authorization_url(
            state="s", nonce="n", code_challenge="c"
        )


def test_a_failing_token_endpoint_is_unavailable_but_a_refused_code_is_a_400(monkeypatch, caplog):
    from fastapi import HTTPException

    _discovery(monkeypatch, ENDPOINTS)
    request = httpx.Request("POST", ENDPOINTS["token_endpoint"])
    client = _client("https://idp.test/realms/x")

    monkeypatch.setattr(
        httpx, "post", lambda url, data, timeout: httpx.Response(503, request=request)
    )
    with pytest.raises(IdentityProviderUnavailable):
        client.exchange(code="c", code_verifier="v")
    assert "OIDC token exchange failed" in caplog.text

    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, data, timeout: httpx.Response(
            400, json={"error": "invalid_grant"}, request=request
        ),
    )
    with pytest.raises(HTTPException) as refused:
        client.exchange(code="c", code_verifier="v")
    assert refused.value.status_code == 400
