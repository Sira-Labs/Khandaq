"""Unit tests for fail-closed production configuration (specs 001, 008, 014)."""

from __future__ import annotations

import pytest

from khandaq.settings import Settings

_PROD_BASE = {
    "env": "prod",
    "session_secret": "a-real-session-secret",
    "database_url": "postgresql://u:p@db/khandaq",
    "evidence_key": "a-real-evidence-key-of-32-characters",
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


def test_prod_worker_does_not_need_oidc():
    # The worker serves no logins, so it is deployed without the OIDC client secret and must boot.
    Settings(**_PROD_BASE, role="worker").validate_runtime()  # must not raise


def test_prod_api_role_still_requires_oidc():
    with pytest.raises(RuntimeError) as exc:
        Settings(**_PROD_BASE, role="api").validate_runtime()
    assert "OIDC" in str(exc.value)


def test_dev_never_fails_closed():
    Settings(env="dev").validate_runtime()  # no raise, even with everything unset


def test_unknown_env_refuses_to_start():
    # Anything but prod enables the dev login stub, so a typo must not silently open the API.
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(env="production")


def test_allow_list_is_case_insensitive_and_includes_admin():
    s = Settings(admin_email="Owner@Example.org", allowed_emails=" a@x.test, B@X.test ")
    assert s.email_allowed("owner@example.org")
    assert s.email_allowed("b@x.test") and s.email_allowed("A@X.TEST")
    assert not s.email_allowed("c@x.test")
    assert not Settings().email_allowed("anyone@x.test")  # empty list + no admin = nobody


_PROD_FULL = {
    **_PROD_BASE,
    "oidc_issuer": "https://idp.example/realms/khandaq",
    "oidc_client_secret": "a-real-client-secret",
    "public_url": "https://khandaq.example",
}


@pytest.mark.parametrize(
    "override, message",
    [
        ({"evidence_key": "too-short-evidence-key"}, "at least 32 characters"),
        ({"evidence_previous_keys": "a" * 40 + ",short"}, "PREVIOUS_KEYS"),
        ({"object_store_url": "https://bucket.example"}, "s3://"),
        ({"object_store_url": "s3://"}, "s3://"),
    ],
)
def test_prod_refuses_bad_evidence_settings(override, message):
    s = Settings(**{**_PROD_FULL, **override})
    with pytest.raises(RuntimeError) as exc:
        s.validate_runtime()
    assert message in str(exc.value)


def test_prod_accepts_s3_store_and_retired_keys():
    s = Settings(
        **_PROD_FULL,
        object_store_url="s3://khandaq-evidence/prod",
        evidence_previous_keys="b" * 32 + ", " + "c" * 44,
    )
    s.validate_runtime()  # must not raise
