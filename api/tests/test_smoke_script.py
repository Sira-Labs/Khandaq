"""The deployment smoke script (spec 019) passes against the real app, authenticated by an API
token, and reports a failing check with exit code 1. Postgres; no network."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "smoke.py"


def _load_smoke():
    spec = importlib.util.spec_from_file_location("khandaq_smoke", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def client():
    from khandaq import main, migrate
    from khandaq.deps import get_session

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

    def _get_session():
        with Session(eng) as s:
            try:
                yield s
            except Exception:
                s.rollback()
                raise

    from khandaq.settings import get_settings

    settings = get_settings()
    previous = (settings.database_url, settings.allowed_emails)
    settings.database_url = TEST_URL  # /api/version reads the schema revision through it
    settings.allowed_emails = "smoke@test"  # token sign-in honours the allow-list, as in prod
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app)
    settings.database_url, settings.allowed_emails = previous
    eng.dispose()


def _transport(client: TestClient, token: str):
    def call(method, path, body=None):
        r = client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        ctype = r.headers.get("content-type", "")
        return r.status_code, r.json() if "application/json" in ctype else r.content

    return call


def _token(client: TestClient) -> str:
    r = client.post(
        "/api/auth/tokens", json={"name": "smoke"}, headers={"X-Khandaq-Dev-User": "smoke@test"}
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_smoke_script_passes_against_the_app(client):
    smoke = _load_smoke()
    lines: list[str] = []
    runner = smoke.Smoke(_transport(client, _token(client)), out=lines.append)
    assert runner.run() is True, "\n".join(lines)
    assert all(line.startswith(("✓", "–")) for line in lines)
    assert len(runner.results) == 10
    # smoke@test is not an organisation admin: the worker check is skipped, not passed.
    assert runner.skipped == ["a worker is alive (spec 023)"]
    assert any("out-of-scope run rejected" in line for line in lines)


@pytest.fixture
def admin_token(client):
    from khandaq.settings import get_settings

    settings = get_settings()
    previous = (settings.admin_email, settings.allowed_emails)
    settings.admin_email = "smoke-admin@test"
    settings.allowed_emails = "smoke@test, smoke-admin@test"
    r = client.post(
        "/api/auth/tokens",
        json={"name": "smoke-admin"},
        headers={"X-Khandaq-Dev-User": "smoke-admin@test"},
    )
    assert r.status_code == 201, r.text
    yield r.json()["token"]
    settings.admin_email, settings.allowed_emails = previous


def _set_heartbeat(seen_minutes_ago: float | None) -> None:
    import datetime as dt

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DELETE FROM worker_heartbeats"))
        if seen_minutes_ago is not None:
            seen = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=seen_minutes_ago)
            conn.execute(
                text(
                    "INSERT INTO worker_heartbeats (id, started_at, seen_at, app_version, summary) "
                    "VALUES ('w:1', :t, :t, '0', :s)"
                ),
                {"t": seen, "s": '{"alerts": {"webhook": true, "email": false}}'},
            )
    eng.dispose()


def test_an_admin_token_checks_that_a_worker_is_alive(client, admin_token):
    smoke = _load_smoke()
    _set_heartbeat(seen_minutes_ago=0.1)
    lines: list[str] = []
    runner = smoke.Smoke(_transport(client, admin_token), out=lines.append)
    assert runner.run() is True, "\n".join(lines)
    assert runner.skipped == [] and len(runner.results) == 11
    assert "✓ a worker is alive (spec 023) — 1 alive; worker alerts: webhook" in lines


def test_no_live_worker_fails_the_smoke_test(client, admin_token):
    smoke = _load_smoke()
    _set_heartbeat(seen_minutes_ago=10)
    lines: list[str] = []
    assert smoke.Smoke(_transport(client, admin_token), out=lines.append).run() is False
    assert lines[-1].startswith("✗ a worker is alive (spec 023): AssertionError: no worker")


def test_smoke_script_reports_a_failing_check_and_cleans_up(client):
    smoke = _load_smoke()
    real = _transport(client, _token(client))
    closed: list[str] = []

    def broken(method, path, body=None):
        if path.endswith("/report/verify"):
            return 500, {"detail": "synthetic failure"}
        if path.endswith("/close"):
            closed.append(path)
        return real(method, path, body)

    lines: list[str] = []
    runner = smoke.Smoke(broken, out=lines.append)
    assert runner.run() is False
    assert lines[-1].startswith("✗ report exports and re-verifies against its pin: SmokeFailure")
    assert closed, "the engagement it created must be closed after a failure"


def test_smoke_script_refuses_an_unmigrated_api():
    smoke = _load_smoke()

    def unmigrated(method, path, body=None):
        if path == "/api/version":
            return 200, {"app": "0.1.0", "schema_revision": "none"}
        return 200, {}

    lines: list[str] = []
    assert smoke.Smoke(unmigrated, out=lines.append).run() is False
    assert lines == [
        "✗ API healthy and migrated: AssertionError: schema revision 'none' is missing or older "
        "than 0011"
    ]


def test_smoke_script_needs_a_token(capsys):
    smoke = _load_smoke()
    assert smoke.main(["--url", "http://localhost:1", "--token", ""]) == 2


def test_a_transport_error_is_reported_and_still_cleans_up(client):
    """A dropped connection mid-run prints a ✗ and closes the engagement (PR #36 review)."""
    import urllib.error

    smoke = _load_smoke()
    real = _transport(client, _token(client))
    closed: list[str] = []

    def flaky(method, path, body=None):
        if path.endswith("/ledger"):
            raise urllib.error.URLError("connection refused")
        if path.endswith("/close"):
            closed.append(path)
        return real(method, path, body)

    lines: list[str] = []
    assert smoke.Smoke(flaky, out=lines.append).run() is False
    assert lines[-1].startswith("✗ evidence ledger verifies: URLError")
    assert closed


def test_a_failed_cleanup_is_reported_without_hiding_the_failure(client):
    import urllib.error

    smoke = _load_smoke()
    real = _transport(client, _token(client))

    def broken(method, path, body=None):
        if path.endswith("/ledger") or path.endswith("/close"):
            raise urllib.error.URLError("connection refused")
        return real(method, path, body)

    lines: list[str] = []
    assert smoke.Smoke(broken, out=lines.append).run() is False
    assert lines[-2].startswith("✗ evidence ledger verifies: URLError")
    assert lines[-1].startswith("! cleanup failed: engagement eng_")


@pytest.mark.parametrize(
    "url, ok",
    [
        ("https://khandaq-stg.example.org", True),
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://khandaq-stg.example.org", False),
        ("ftp://khandaq.example.org", False),
        ("khandaq.example.org", False),
    ],
)
def test_the_token_is_only_sent_over_https_or_to_localhost(url, ok):
    smoke = _load_smoke()
    if ok:
        smoke.http_transport(url, "khq_synthetic")
    else:
        with pytest.raises(ValueError):
            smoke.http_transport(url, "khq_synthetic")
    assert smoke.main(["--url", "http://khandaq.example.org", "--token", "khq_synthetic"]) == 2


def test_redirects_are_not_followed():
    """A 302 comes back as the answer; the token never travels to the Location."""
    import http.server
    import threading

    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            hits.append(self.path)
            if self.path == "/api/health":
                self.send_response(302)
                self.send_header("Location", "/stolen")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        smoke = _load_smoke()
        call = smoke.http_transport(f"http://127.0.0.1:{server.server_port}", "khq_synthetic")
        status, _ = call("GET", "/api/health")
        assert status == 302
        assert hits == ["/api/health"]
    finally:
        server.shutdown()
