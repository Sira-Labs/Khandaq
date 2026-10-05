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
        (
            {"alert_webhook_url": "http://hooks.example", "alert_webhook_secret": "s" * 40},
            "https://",
        ),
        ({"alert_webhook_url": "https://hooks.example", "alert_webhook_secret": "short"}, "SECRET"),
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
        alert_webhook_url="https://hooks.example/khandaq",
        alert_webhook_secret="d" * 40,
    )
    s.validate_runtime()  # must not raise


# --- Email alerts (spec 022) ---------------------------------------------------------------------

_EMAIL = {
    "alert_email_to": "secops@acme.example, oncall@acme.example",
    "alert_email_from": "khandaq@acme.example",
}


def test_prod_accepts_email_alerts_over_tls():
    for url in ("smtps://khandaq@mail.acme.example", "smtp+starttls://mail.acme.example:2587"):
        Settings(
            **_PROD_FULL, **_EMAIL, smtp_url=url, smtp_password="a-real-password"
        ).validate_runtime()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"smtp_url": "smtp://mail.acme.example"}, r"smtps:// or smtp\+starttls://"),
        ({"smtp_url": "smtps://khandaq@mail.acme.example"}, "KHANDAQ_SMTP_PASSWORD"),
    ],
)
def test_prod_refuses_email_without_tls_or_password(overrides, message):
    with pytest.raises(RuntimeError, match=message):
        Settings(**_PROD_FULL, **_EMAIL, **overrides).validate_runtime()


@pytest.mark.parametrize("env", ["dev", "prod"])
@pytest.mark.parametrize(
    ("overrides", "error", "message"),
    [
        ({"smtp_url": "ftp://mail.acme.example"}, ValueError, "KHANDAQ_SMTP_URL"),
        ({"smtp_url": "smtps://u:pw@mail.acme.example"}, ValueError, "password"),
        ({"smtp_url": "smtps://mail.acme.example:notaport"}, ValueError, "port"),
        ({"smtp_url": ""}, RuntimeError, "KHANDAQ_SMTP_URL is not"),
        ({"smtp_url": "smtp://localhost:1025", "alert_email_from": ""}, RuntimeError, "addresses"),
        (
            {"smtp_url": "smtp://localhost:1025", "alert_email_to": "not-an-address"},
            RuntimeError,
            "addresses",
        ),
    ],
)
def test_bad_email_settings_stop_startup_everywhere(env, overrides, error, message):
    base = _PROD_FULL if env == "prod" else {"env": "dev"}
    with pytest.raises(error, match=message):
        Settings(**{**base, **_EMAIL, **overrides}).validate_runtime()


def test_dev_allows_a_plain_local_catcher():
    Settings(env="dev", **_EMAIL, smtp_url="smtp://localhost:1025").validate_runtime()


@pytest.mark.parametrize(
    "url",
    [
        "https://$$cap_appname-web.apps.example.org",  # an unfilled CapRover one-click default
        "http://khandaq.example",
        "https://khandaq.example/console",
        "https://user@khandaq.example",
        "khandaq.example",
        "https://khandaq.example:99999",
    ],
)
def test_prod_refuses_a_public_url_that_is_not_an_https_origin(url):
    with pytest.raises(RuntimeError, match="KHANDAQ_PUBLIC_URL"):
        Settings(**{**_PROD_FULL, "public_url": url}).validate_runtime()


@pytest.mark.parametrize("url", ["https://khandaq.example", "https://khandaq.example:8443/"])
def test_prod_accepts_a_public_https_origin(url):
    Settings(**{**_PROD_FULL, "public_url": url}).validate_runtime()  # must not raise


def test_prod_refuses_an_issuer_with_an_unfilled_placeholder():
    issuer = "https://$$cap_keycloak.example/realms/khandaq"
    with pytest.raises(RuntimeError, match="KHANDAQ_OIDC_ISSUER"):
        Settings(**{**_PROD_FULL, "oidc_issuer": issuer}).validate_runtime()
