"""Smoke tests for the bootable API skeleton."""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client() -> TestClient:
    # Import fresh so settings pick up the test environment.
    from khandaq import main

    importlib.reload(main)
    return TestClient(main.app)


def test_health_ok() -> None:
    r = _client().get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_version_reports_app_and_schema() -> None:
    r = _client().get("/api/version")
    assert r.status_code == 200
    body = r.json()
    assert body["app"]
    # No database configured in tests → schema is reported as "none", never an error.
    assert body["schema_revision"] == "none"


def test_prod_fails_closed_on_placeholder_secret(monkeypatch) -> None:
    monkeypatch.setenv("KHANDAQ_ENV", "prod")
    monkeypatch.setenv("KHANDAQ_SESSION_SECRET", "changeme")
    monkeypatch.setenv("KHANDAQ_DATABASE_URL", "postgresql+psycopg://x:y@db:5432/k")
    monkeypatch.setenv("KHANDAQ_EVIDENCE_KEY", "deadbeefdeadbeefdeadbeefdeadbeef")
    from khandaq.settings import Settings

    try:
        Settings().validate_runtime()
    except RuntimeError as exc:
        assert "SESSION_SECRET" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("prod must refuse a placeholder session secret")
