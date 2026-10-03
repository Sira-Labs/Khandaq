"""Spec 023: worker heartbeats and GET /api/deployment."""

from __future__ import annotations

import datetime as dt
import json
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

ADMIN = {"X-Khandaq-Dev-User": "dev@khandaq.local"}  # the dev stub's default admin
MEMBER = {"X-Khandaq-Dev-User": "member@test"}

SECRETS = {
    "session_secret": "session-secret-value-0123456789abcdef",
    "evidence_key": "evidence-key-value-0123456789abcdefgh",
    "evidence_previous_keys": "retired-key-value-0123456789abcdefg",
    "alert_webhook_url": "https://hooks.example.invalid/secret-path-xyz",
    "alert_webhook_secret": "webhook-secret-value-0123456789abcdef",
    "alert_email_to": "secops@acme.example",
    "alert_email_from": "khandaq@acme.example",
    "smtp_url": "smtps://relay-user@mail.acme.example",
    "smtp_password": "smtp-password-value-0123456789",
    "object_store_secret_access_key": "s3-secret-value-0123456789abcdef",
}


@pytest.fixture(scope="module")
def env():
    from khandaq import main, migrate
    from khandaq.deps import get_session
    from khandaq.settings import get_settings

    engine = create_engine(TEST_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)

    def _get_session():
        with Session(engine) as s:
            try:
                yield s
            except Exception:
                s.rollback()
                raise

    settings = get_settings()
    previous = {k: getattr(settings, k) for k in [*SECRETS, "admin_email"]}
    for k, v in SECRETS.items():
        setattr(settings, k, v)
    settings.admin_email = ""
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), engine
    for k, v in previous.items():
        setattr(settings, k, v)
    engine.dispose()


def test_a_worker_beats_on_start_then_at_most_every_interval(env):
    from khandaq.models import WorkerHeartbeat
    from khandaq.settings import get_settings
    from khandaq.worker import Heartbeat

    _, engine = env
    beat = Heartbeat(get_settings(), every=30.0)
    assert beat.maybe_beat(engine) is True
    assert beat.maybe_beat(engine) is False  # throttled
    with Session(engine) as s:
        row = s.get(WorkerHeartbeat, beat.wid)
        assert row is not None and row.summary["role"] == get_settings().role
        first_seen = row.seen_at
    beat._last = None  # as if the interval had passed
    assert beat.maybe_beat(engine) is True
    with Session(engine) as s:
        assert s.get(WorkerHeartbeat, beat.wid).seen_at > first_seen


def test_week_old_heartbeats_are_pruned_on_start(env):
    from khandaq.settings import get_settings
    from khandaq.worker import Heartbeat

    _, engine = env
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=8)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO worker_heartbeats (id, started_at, seen_at, app_version, summary) "
                "VALUES ('gone:1', :t, :t, '0', '{}')"
            ),
            {"t": old},
        )
    Heartbeat(get_settings()).maybe_beat(engine)
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT 1 FROM worker_heartbeats WHERE id = 'gone:1'")).first()
            is None
        )


def test_the_status_shows_api_and_workers_without_secrets(env):
    from khandaq.settings import get_settings
    from khandaq.worker import Heartbeat

    client, engine = env
    Heartbeat(get_settings()).maybe_beat(engine)
    stale = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO worker_heartbeats (id, started_at, seen_at, app_version, summary) "
                "VALUES ('stale:2', :t, :t, '0', '{}')"
            ),
            {"t": stale},
        )

    r = client.get("/api/deployment", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    summary = body["api"]["summary"]
    assert summary["alerts"] == {"webhook": True, "email": True}
    assert summary["evidence"] == {"key": True, "retired_keys": 1, "store": "local", "bucket": None}
    assert summary["mappings"]["versions"]["atlas"]
    by_id = {w["id"]: w for w in body["workers"]}
    assert by_id["stale:2"]["alive"] is False
    assert any(w["alive"] for w in body["workers"])

    raw = json.dumps(body)
    for name, value in SECRETS.items():
        assert value not in raw, f"{name} leaked into /api/deployment"
    assert "mail.acme.example" not in raw and "hooks.example.invalid" not in raw


def test_only_organisation_admins_may_read_it(env):
    client, _ = env
    assert client.get("/api/deployment", headers=MEMBER).status_code == 403
    assert client.get("/api/deployment", headers=ADMIN).status_code == 200
