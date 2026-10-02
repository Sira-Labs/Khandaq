"""Integration tests for run execution (spec 005): scope lock on the run path, the echo pipeline,
dedup in the inbox, and sealed evidence. Requires Postgres + the khandaq_core wheel."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}

SCOPE = {
    "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
    "deny": [],
    "roe": {},
}


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

    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app)
    eng.dispose()


def _active_engagement(client, name, target_spec):
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": target_spec},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    return eng_id, tid


def test_authorised_run_executes_normalises_and_seals(client):
    eng_id, tid = _active_engagement(
        client, "run-ok", {"host": "gw.acme.test", "model": "assistant-v3"}
    )

    r = client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    assert r.status_code == 201, r.text
    assert r.json()["state"] == "succeeded"

    # Inbox: the echo adapter emits 3 raw findings; two collapse → 2 canonical.
    inbox = client.get(f"/api/engagements/{eng_id}/findings", headers=OWNER).json()
    assert len(inbox) == 2
    by_sev = {f["severity"] for f in inbox}
    assert "high" in by_sev and "low" in by_sev
    merged = next(f for f in inbox if f["severity"] == "high")
    assert len(merged["evidence"]) == 2  # merged evidence from both duplicates
    assert any(m["id"] == "LLM01" for m in merged["mappings"])

    # Evidence is sealed and the ledger verifies.
    led = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    assert led["verify"]["ok"] is True
    assert len(led["entries"]) == 3

    # severity filter
    highs = client.get(f"/api/engagements/{eng_id}/findings?severity=high", headers=OWNER).json()
    assert len(highs) == 1


def test_out_of_scope_run_is_rejected_and_audited(client):
    # Target's host is in scope, but we add a second, out-of-scope target and run against it.
    eng_id, _ = _active_engagement(
        client, "run-reject", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    bad_tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "evil.test"}},
        headers=OWNER,
    )
    # targets can only be added in draft; this engagement is active, so the add is refused.
    assert bad_tid.status_code == 409

    # Build a separate engagement left in draft with an out-of-scope target to exercise rejection.
    eng2 = client.post("/api/engagements", json={"name": "reject2"}, headers=OWNER).json()["id"]
    t2 = client.post(
        f"/api/engagements/{eng2}/targets",
        json={"type": "llm_endpoint", "spec": {"host": "evil.test"}},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng2}/scope", json=SCOPE, headers=OWNER)
    client.post(
        f"/api/engagements/{eng2}/activate", json={"authorisation_ref": "SOW-2"}, headers=OWNER
    )

    r = client.post(
        f"/api/engagements/{eng2}/runs", json={"adapter": "echo", "target_id": t2}, headers=OWNER
    )
    assert r.status_code == 201
    body = r.json()
    assert body["state"] == "rejected"
    assert "allow-list" in body["reject_reason"]

    # No findings produced, and the rejection is in the audit log.
    assert client.get(f"/api/engagements/{eng2}/findings", headers=OWNER).json() == []
    actions = [
        a["action"] for a in client.get(f"/api/engagements/{eng2}/audit", headers=OWNER).json()
    ]
    assert "run.rejected" in actions


def test_unknown_adapter_and_target(client):
    eng_id, tid = _active_engagement(
        client, "run-errs", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    assert (
        client.post(
            f"/api/engagements/{eng_id}/runs",
            json={"adapter": "nope", "target_id": tid},
            headers=OWNER,
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/engagements/{eng_id}/runs",
            json={"adapter": "echo", "target_id": "tgt_missing"},
            headers=OWNER,
        ).status_code
        == 404
    )
