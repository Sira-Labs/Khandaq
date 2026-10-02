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
    tc = TestClient(app)
    tc.engine = eng  # direct DB access for assertions the API does not expose
    yield tc
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


# --- review hardening: durable run records, cross-run dedup, refusals, read-only users ---------


def _audit_actions(client, eng_id):
    return [
        a["action"] for a in client.get(f"/api/engagements/{eng_id}/audit", headers=OWNER).json()
    ]


def _run(client, eng_id, tid):
    r = client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_findings_are_deduplicated_across_runs(client):
    eng_id, tid = _active_engagement(
        client, "cross-run", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    first, second = _run(client, eng_id, tid), _run(client, eng_id, tid)
    assert first["state"] == second["state"] == "succeeded"

    # The same two issues found twice stay two canonical findings (they used to double to four).
    inbox = client.get(f"/api/engagements/{eng_id}/findings", headers=OWNER).json()
    assert len(inbox) == 2
    report = client.get(f"/api/engagements/{eng_id}/report", headers=OWNER).json()
    assert report["summary"]["total"] == 2
    # The second run's sightings are kept, linked to the canonical rows, with evidence merged.
    with client.engine.connect() as conn:
        rows = conn.execute(
            text("SELECT canonical, dedup_of, run_id FROM findings WHERE engagement_id = :e"),
            {"e": eng_id},
        ).all()
    linked = [r for r in rows if not r.canonical]
    assert len(rows) == 4 and len(linked) == 2
    assert all(r.dedup_of and r.run_id == second["id"] for r in linked)
    merged = next(f for f in inbox if f["severity"] == "high")
    assert len(merged["evidence"]) == 4  # 2 per run
    ledger = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    assert ledger["verify"]["ok"] and len(ledger["entries"]) == 6


def test_database_failure_while_saving_results_keeps_the_run_record(client, monkeypatch):
    """The adapter has already reached the target; a DB error afterwards must not erase the run."""
    eng_id, tid = _active_engagement(
        client, "db-fail", {"host": "gw.acme.test", "model": "assistant-v3"}
    )

    def poisoned_seal(session, **_kw):
        session.execute(text("SELECT 1/0"))  # aborts the transaction, like a constraint violation

    monkeypatch.setattr("khandaq.runs.seal_evidence", poisoned_seal)
    run = _run(client, eng_id, tid)
    assert run["state"] == "failed" and "recording results failed" in run["reject_reason"]
    persisted = client.get(f"/api/engagements/{eng_id}/runs/{run['id']}", headers=OWNER).json()
    assert persisted["state"] == "failed"
    actions = _audit_actions(client, eng_id)
    assert "run.started" in actions and "run.failed" in actions


def test_adapter_crash_is_recorded(client, monkeypatch):
    eng_id, tid = _active_engagement(
        client, "adapter-crash", {"host": "gw.acme.test", "model": "assistant-v3"}
    )

    def crash(self, request):
        raise RuntimeError("tool exited 137")

    monkeypatch.setattr("khandaq.adapters.runner.EchoRunner.run", crash)
    run = _run(client, eng_id, tid)
    assert run["state"] == "failed" and "tool exited 137" in run["reject_reason"]
    assert "run.failed" in _audit_actions(client, eng_id)


def test_refusals_before_the_scope_check_are_audited(client):
    eng_id, _ = _active_engagement(
        client, "refused", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    other_id, other_tid = _active_engagement(
        client, "other", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    probe = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "echo", "target_id": other_tid},  # another engagement's target
        headers=OWNER,
    )
    assert probe.status_code == 404
    assert "run.refused" in _audit_actions(client, eng_id)


def test_org_read_only_users_cannot_launch_runs(client):
    eng_id, tid = _active_engagement(
        client, "read-only", {"host": "gw.acme.test", "model": "assistant-v3"}
    )
    reader = {"X-Khandaq-Dev-User": "reader@test"}
    client.get("/api/engagements", headers=reader)  # creates the user via the dev stub
    with client.engine.begin() as conn:
        uid = conn.execute(text("SELECT id FROM users WHERE email = 'reader@test'")).scalar_one()
        conn.execute(text("UPDATE users SET org_role = 'read_only' WHERE id = :u"), {"u": uid})
        conn.execute(
            text(
                "INSERT INTO engagement_members (engagement_id, user_id, role) "
                "VALUES (:e, :u, 'operator')"
            ),
            {"e": eng_id, "u": uid},
        )
    r = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "echo", "target_id": tid},
        headers=reader,
    )
    assert r.status_code == 403  # capped at viewer despite the operator membership
    assert client.get(f"/api/engagements/{eng_id}/findings", headers=reader).status_code == 200
