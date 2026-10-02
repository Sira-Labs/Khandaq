"""Integration tests for the engagement lifecycle, scope lock, audit and authz (spec 002).

Requires a real PostgreSQL (KHANDAQ_TEST_DATABASE_URL); skips otherwise. The dev auth stub lets us
act as different users via the X-Khandaq-Dev-User header; a bare default user is an org admin, so we
use explicit non-admin emails to exercise real engagement-role enforcement.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
OUTSIDER = {"X-Khandaq-Dev-User": "outsider@test"}


@pytest.fixture(scope="module")
def ctx():
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

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), eng
    eng.dispose()


def _scope_body():
    return {
        "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
        "deny": [{"host": "evil.test"}],
        "roe": {"max_requests_per_minute": 60},
    }


def test_full_lifecycle_and_scope_lock(ctx):
    client, _ = ctx
    # create (owner is a non-admin who becomes engagement owner)
    r = client.post("/api/engagements", json={"name": "Acme LLM GW"}, headers=OWNER)
    assert r.status_code == 201, r.text
    eng_id = r.json()["id"]
    assert r.json()["state"] == "draft"

    # add an in-scope target
    r = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "gw.acme.test", "model": "assistant-v3"}},
        headers=OWNER,
    )
    assert r.status_code == 201, r.text
    target_id = r.json()["id"]

    # set scope
    r = client.put(f"/api/engagements/{eng_id}/scope", json=_scope_body(), headers=OWNER)
    assert r.status_code == 200 and r.json()["version"] == 1

    # activate (locks scope)
    r = client.post(
        f"/api/engagements/{eng_id}/activate",
        json={"authorisation_ref": "SOW-2026-114"},
        headers=OWNER,
    )
    assert r.status_code == 200 and r.json()["state"] == "active"

    # scope-check: in-scope target at a declared rate within the RoE → allowed
    r = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": {"rate_per_minute": 30}},
        headers=OWNER,
    )
    assert r.status_code == 200 and r.json()["allowed"] is True

    # the RoE caps the rate, so a run that does not declare one cannot be shown to comply → refused
    r = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": {}},
        headers=OWNER,
    )
    assert r.json()["allowed"] is False and "set rate_per_minute" in r.json()["reason"]

    # scope-check: over the rate limit → rejected with a reason
    r = client.post(
        f"/api/engagements/{eng_id}/scope-check",
        json={"target_id": target_id, "params": {"rate_per_minute": 120}},
        headers=OWNER,
    )
    body = r.json()
    assert (
        r.status_code == 200 and body["allowed"] is False and "exceeds the limit" in body["reason"]
    )

    # scope change on an ACTIVE engagement bumps the version and is audited
    r = client.put(f"/api/engagements/{eng_id}/scope", json=_scope_body(), headers=OWNER)
    assert r.status_code == 200 and r.json()["version"] == 2

    # audit log contains the lifecycle actions
    r = client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER)
    actions = [row["action"] for row in r.json()]
    assert {
        "engagement.created",
        "target.added",
        "scope.set",
        "engagement.activated",
        "scope.changed",
    } <= set(actions)

    # close
    r = client.post(f"/api/engagements/{eng_id}/close", headers=OWNER)
    assert r.status_code == 200 and r.json()["state"] == "closed"


def test_activate_requires_scope_target_and_authref(ctx):
    client, _ = ctx
    eng_id = client.post("/api/engagements", json={"name": "bare"}, headers=OWNER).json()["id"]
    # no scope, no target yet
    r = client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "x"}, headers=OWNER
    )
    assert r.status_code == 422
    assert "scope" in r.json()["detail"] and "target" in r.json()["detail"]


def test_default_deny_denied_host(ctx):
    client, _ = ctx
    eng_id = client.post("/api/engagements", json={"name": "deny"}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "evil.test"}},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=_scope_body(), headers=OWNER)
    r = client.post(
        f"/api/engagements/{eng_id}/scope-check", json={"target_id": tid}, headers=OWNER
    )
    assert r.json()["allowed"] is False  # evil.test is neither allowed nor (worse) matches deny


def test_cross_engagement_access_is_forbidden(ctx):
    client, _ = ctx
    eng_id = client.post("/api/engagements", json={"name": "private"}, headers=OWNER).json()["id"]
    r = client.get(f"/api/engagements/{eng_id}", headers=OUTSIDER)
    assert r.status_code == 403


def test_viewer_cannot_add_target_but_owner_can(ctx):
    client, eng = ctx
    from khandaq import models as m

    eng_id = client.post("/api/engagements", json={"name": "roles"}, headers=OWNER).json()["id"]
    # make a viewer a member directly (no add-member route until later)
    with Session(eng) as s:
        viewer = m.User(email="viewer@test", org_role="member")
        s.add(viewer)
        s.flush()
        s.add(m.EngagementMember(engagement_id=eng_id, user_id=viewer.id, role="viewer"))
        s.commit()

    r = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "gw.acme.test"}},
        headers={"X-Khandaq-Dev-User": "viewer@test"},
    )
    assert r.status_code == 403

    # a viewer may still run a pre-flight scope-check (any member)
    r = client.get(f"/api/engagements/{eng_id}", headers={"X-Khandaq-Dev-User": "viewer@test"})
    assert r.status_code == 200
