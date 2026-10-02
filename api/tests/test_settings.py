"""Unit tests for fail-closed production configuration (spec 008 extends spec 001)."""

from __future__ import annotations

import pytest

from khandaq.settings import Settings

_PROD_BASE = {
    "env": "prod",
    "session_secret": "a-real-session-secret",
    "database_url": "postgresql://u:p@db/khandaq",
    "evidence_key": "a-real-evidence-key",
}


def test_prod_requires_oidc_settings():
    s = Settings(**_PROD_BASE)  # OIDC unset
    with pytest.raises(RuntimeError) as exc:
        s.validate_runtime()
    assert "OIDC" in str(exc.value)


def test_prod_passes_with_full_config():
    s = Settings(
        **_PROD_BASE,
        oidc_issuer="https://idp.example/realms/khandaq",
        oidc_client_secret="a-real-client-secret",
        public_url="https://khandaq.example",
    )
    s.validate_runtime()  # must not raise
    assert s.oidc_configured is True


def test_dev_never_fails_closed():
    Settings(env="dev").validate_runtime()  # no raise, even with everything unset
