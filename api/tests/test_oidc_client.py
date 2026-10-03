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


def test_a_discovery_document_without_endpoints_is_rejected(monkeypatch):
    request = httpx.Request("GET", "https://idp.test/realms/x/.well-known/openid-configuration")
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, timeout: httpx.Response(200, json={"issuer": "x"}, request=request),
    )
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
