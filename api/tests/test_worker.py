"""Container runs on the worker (spec 012 behaviours 1, 2, 5–7; ADR-0015).

The API queues a container run; the worker claims it, re-checks the scope lock, executes it and
records the outcome. The container is replaced by a fake runner returning what ``DockerRunner``
returns, so this needs Postgres but no Docker daemon.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from khandaq.adapters.manifest import AdapterManifest

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}
TARGET = {"host": "gw.acme.test", "base_url": "https://gw.acme.test/v1", "model": "assistant-v3"}
SCOPE = {
    "allow": {"llm_endpoint": [{"host": "gw.acme.test", "models": ["assistant-v3"]}]},
    "deny": [],
    "roe": {},
}
CONTAINER = AdapterManifest(
    name="garak",
    version="0.17.0",
    phases=["03-scanning"],
    severity_table={"high": "high"},
    image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
)


class FakeRunner:
    """Returns what DockerRunner returns for a run: findings and evidence with content."""

    def __init__(self, error: Exception | None = None) -> None:
        self.requests: list[dict] = []
        self.error = error

    def run(self, request: dict) -> dict:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        content = b'{"probe":"promptinject.HijackHateHumans","passed":3,"total_evaluated":10}\n'
        return {
            "evidence": [
                {
                    "local_id": "garak.report.jsonl",
                    "kind": "report",
                    "object_key": "{engagement_id}/{run_id}/garak.report.jsonl".format(**request),
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                    "redacted": False,
                    "content": content,
                }
            ],
            "findings": [
                {
                    "schema": "khandaq.finding/2",
                    "engagement_id": request["engagement_id"],
                    "run_id": request["run_id"],
                    "rule_id": "garak.promptinject.hijack",
                    "severity": "high",
                    "source": {"tool": "garak", "version": "0.17.0"},
                    "locations": [{"logicalLocations": [{"fullyQualifiedName": "promptinject"}]}],
                    "x-khandaq": {"phase": "04-prompt-injection", "mappings": []},
                    "_evidence_local": ["garak.report.jsonl"],
                }
            ],
        }


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    from khandaq import main, migrate
    from khandaq.deps import get_session
    from khandaq.settings import get_settings

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

    settings = get_settings()
    previous = (settings.evidence_dir, settings.evidence_key, settings.object_store_url)
    settings.evidence_dir = str(tmp_path_factory.mktemp("evidence"))
    settings.evidence_key = "synthetic-test-evidence-key-0123456789"  # local store, encrypted
    settings.object_store_url = ""
    app = main.create_app()
    app.dependency_overrides[get_session] = _get_session
    yield TestClient(app), eng, settings
    settings.evidence_dir, settings.evidence_key, settings.object_store_url = previous
    eng.dispose()


@pytest.fixture(autouse=True)
def container_adapter(monkeypatch):
    """Make 'garak' a known container adapter for the run service (the registry loads disk
    manifests in part 3)."""
    from khandaq import runs

    real = runs.get_manifest
    monkeypatch.setattr(
        runs, "get_manifest", lambda name: CONTAINER if name == "garak" else real(name)
    )


def _engagement(client, name: str) -> tuple[str, str]:
    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    tid = client.post(
        f"/api/engagements/{eng_id}/targets",
        json={"type": "llm_endpoint", "spec": TARGET},
        headers=OWNER,
    ).json()["id"]
    client.put(f"/api/engagements/{eng_id}/scope", json=SCOPE, headers=OWNER)
    client.post(
        f"/api/engagements/{eng_id}/activate", json={"authorisation_ref": "SOW-1"}, headers=OWNER
    )
    return eng_id, tid


def _queue(client, eng_id: str, tid: str) -> dict:
    r = client.post(
        f"/api/engagements/{eng_id}/runs",
        json={"adapter": "garak", "target_id": tid},
        headers=OWNER,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _actions(db, run_id: str) -> list[str]:
    with db.connect() as conn:
        return list(
            conn.execute(
                text("SELECT action FROM audit_log WHERE detail->>'run_id' = :r ORDER BY at, id"),
                {"r": run_id},
            ).scalars()
        )


def _run(client, eng_id: str, run_id: str) -> dict:
    return client.get(f"/api/engagements/{eng_id}/runs/{run_id}", headers=OWNER).json()


def test_a_container_run_is_queued_not_executed_by_the_api(env):
    client, db, _ = env
    eng_id, tid = _engagement(client, "queued")
    run = _queue(client, eng_id, tid)
    assert run["state"] == "queued"
    assert _actions(db, run["id"]) == ["run.queued"]


def test_the_worker_executes_a_queued_run_and_keeps_its_evidence(env):
    from khandaq import worker

    client, db, settings = env
    eng_id, tid = _engagement(client, "executed")
    run = _queue(client, eng_id, tid)
    runner = FakeRunner()

    assert worker.drain(db, runner=runner) >= 1

    assert _run(client, eng_id, run["id"])["state"] == "succeeded"
    assert _actions(db, run["id"]) == ["run.queued", "run.started", "run.succeeded"]
    # The adapter got exactly the authorised target.
    [request] = [r for r in runner.requests if r["run_id"] == run["id"]]
    assert request["target"] == {"type": "llm_endpoint", "spec": TARGET}
    inbox = client.get(f"/api/engagements/{eng_id}/findings", headers=OWNER).json()
    assert [f["rule_id"] for f in inbox] == ["garak.promptinject.hijack"]
    # Evidence bytes are retained write-once and encrypted under their object key (spec 014), and
    # the ledger verifies.
    key = f"{eng_id}/{run['id']}/garak.report.jsonl"
    stored = os.path.join(settings.evidence_dir, key)
    blob = open(stored, "rb").read()
    assert blob.startswith(b"KHQE") and b'"probe"' not in blob
    assert not os.access(stored, os.W_OK) or os.geteuid() == 0
    ledger = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    assert ledger["verify"]["ok"] is True and len(ledger["entries"]) == 1


def test_the_scope_is_checked_again_when_the_worker_claims_the_run(env):
    """Queued under one scope, claimed under a narrower one: the run is rejected, not launched."""
    from khandaq import worker

    client, db, _ = env
    eng_id, tid = _engagement(client, "rechecked")
    run = _queue(client, eng_id, tid)
    narrowed = {**SCOPE, "deny": [{"host": "gw.acme.test"}]}
    assert client.put(f"/api/engagements/{eng_id}/scope", json=narrowed, headers=OWNER).is_success
    runner = FakeRunner()

    worker.drain(db, runner=runner)

    after = _run(client, eng_id, run["id"])
    assert after["state"] == "rejected" and "deny" in after["reject_reason"]
    assert all(r["run_id"] != run["id"] for r in runner.requests)
    assert _actions(db, run["id"]) == ["run.queued", "run.rejected"]


def test_a_closed_engagement_stops_its_queued_runs(env):
    from khandaq import worker

    client, db, _ = env
    eng_id, tid = _engagement(client, "closed")
    run = _queue(client, eng_id, tid)
    assert client.post(f"/api/engagements/{eng_id}/close", headers=OWNER).is_success
    worker.drain(db, runner=FakeRunner())
    assert _run(client, eng_id, run["id"])["state"] == "rejected"


def test_an_adapter_failure_is_recorded(env):
    from khandaq import worker

    client, db, _ = env
    eng_id, tid = _engagement(client, "failing")
    run = _queue(client, eng_id, tid)
    worker.drain(db, runner=FakeRunner(error=RuntimeError("adapter exited with 2: no report")))
    after = _run(client, eng_id, run["id"])
    assert after["state"] == "failed" and "no report" in after["reject_reason"]
    assert _actions(db, run["id"])[-1] == "run.failed"


def test_concurrent_workers_claim_different_runs(env):
    from khandaq.runs import claim_next_run

    client, db, _ = env
    with db.begin() as conn:  # an empty queue apart from this test's runs
        conn.execute(text("UPDATE runs SET state = 'failed' WHERE state = 'queued'"))
    eng_id, tid = _engagement(client, "concurrent")
    first, second = _queue(client, eng_id, tid), _queue(client, eng_id, tid)
    with Session(db) as holder:
        # Another worker is in the middle of claiming the oldest run (it holds the row lock).
        holder.execute(
            text("SELECT id FROM runs WHERE id = :r FOR UPDATE"), {"r": first["id"]}
        ).all()
        with Session(db) as other:
            assert claim_next_run(other) == second["id"]
        holder.rollback()


def test_runs_a_lost_worker_left_running_are_failed_at_start(env):
    from khandaq.runs import recover_stale_runs

    client, db, _ = env
    eng_id, tid = _engagement(client, "stale")
    run = _queue(client, eng_id, tid)
    fresh = _queue(client, eng_id, tid)
    long_ago = dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)
    with db.begin() as conn:
        conn.execute(
            text("UPDATE runs SET state = 'running', started_at = :t WHERE id = :r"),
            {"t": long_ago, "r": run["id"]},
        )
        conn.execute(
            text("UPDATE runs SET state = 'running', started_at = now() WHERE id = :r"),
            {"r": fresh["id"]},
        )
    with Session(db) as session:
        assert recover_stale_runs(session, older_than=dt.timedelta(hours=1)) == 1
    assert _run(client, eng_id, run["id"])["state"] == "failed"
    assert _run(client, eng_id, fresh["id"])["state"] == "running"  # a live run is left alone
    assert _actions(db, run["id"])[-1] == "run.failed"


def test_a_queued_run_wakes_a_listening_worker(env):
    from khandaq.worker import Notifications

    client, db, _ = env
    eng_id, tid = _engagement(client, "notify")
    listener = Notifications(db)
    try:
        started = time.monotonic()
        _queue(client, eng_id, tid)
        listener.wait(timeout=10)
        assert time.monotonic() - started < 5
    finally:
        listener.close()


# --- spec 014: encrypted evidence, download by role --------------------------------------------


def _executed_run(client, db, name: str) -> tuple[str, str, dict]:
    """A container run the worker executed; returns (engagement, run id, its evidence entry)."""
    from khandaq import worker

    eng_id, tid = _engagement(client, name)
    run = _queue(client, eng_id, tid)
    worker.drain(db, runner=FakeRunner())
    assert _run(client, eng_id, run["id"])["state"] == "succeeded"
    ledger = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()
    [entry] = [e for e in ledger["entries"]]
    return eng_id, run["id"], entry


def _audit(db, eng_id: str, action: str) -> list[dict]:
    with db.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT detail FROM audit_log WHERE engagement_id = :e AND action = :a "
                    "ORDER BY at, id"
                ),
                {"e": eng_id, "a": action},
            ).scalars()
        )


def _add_member(db, eng_id: str, email: str, role: str) -> dict:
    from khandaq import models as m

    with Session(db) as s:
        user = s.query(m.User).filter_by(email=email).one_or_none()
        if user is None:
            user = m.User(email=email, org_role="member")
            s.add(user)
            s.flush()
        s.add(m.EngagementMember(engagement_id=eng_id, user_id=user.id, role=role))
        s.commit()
    return {"X-Khandaq-Dev-User": email}


def test_evidence_download_returns_the_sealed_bytes_and_is_audited(env):
    client, db, _ = env
    eng_id, run_id, entry = _executed_run(client, db, "download")
    url = f"/api/engagements/{eng_id}/evidence/{entry['evidence_id']}/content"

    r = client.get(url, headers=OWNER)
    assert r.status_code == 200
    assert r.content.startswith(b'{"probe":"promptinject.HijackHateHumans"')
    sealed = "sha256:" + hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-khandaq-evidence-sha256"] == sealed
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["content-disposition"] == (
        f'attachment; filename="{entry["evidence_id"]}-garak.report.jsonl"'
    )
    assert _audit(db, eng_id, "evidence.downloaded") == [
        {"evidence_id": entry["evidence_id"], "sha256": sealed, "bytes": len(r.content)}
    ]

    analyst = _add_member(db, eng_id, "evidence-analyst@test", "analyst")
    assert client.get(url, headers=analyst).status_code == 200


def test_evidence_download_authz(env):
    client, db, _ = env
    eng_id, _, entry = _executed_run(client, db, "download-authz")
    url = f"/api/engagements/{eng_id}/evidence/{entry['evidence_id']}/content"

    viewer = _add_member(db, eng_id, "evidence-viewer@test", "viewer")
    assert client.get(url, headers=viewer).status_code == 403
    outsider = {"X-Khandaq-Dev-User": "evidence-outsider@test"}
    assert client.get(url, headers=outsider).status_code == 403
    # Another engagement's evidence id is not found here, even for that engagement's owner.
    other_eng, _ = _engagement(client, "download-other")
    r = client.get(
        f"/api/engagements/{other_eng}/evidence/{entry['evidence_id']}/content", headers=OWNER
    )
    assert r.status_code == 404
    assert _audit(db, eng_id, "evidence.downloaded") == []


def test_evidence_without_stored_bytes_is_404(env):
    client, _, _ = env
    eng_id, tid = _engagement(client, "download-echo")
    r = client.post(
        f"/api/engagements/{eng_id}/runs", json={"adapter": "echo", "target_id": tid}, headers=OWNER
    )
    assert r.status_code == 201, r.text
    entry = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()["entries"][0]
    r = client.get(
        f"/api/engagements/{eng_id}/evidence/{entry['evidence_id']}/content", headers=OWNER
    )
    assert r.status_code == 404
    assert r.json()["detail"] == "no stored content for this evidence"


def test_tampered_evidence_is_refused_and_audited(env):
    client, db, settings = env
    eng_id, run_id, entry = _executed_run(client, db, "download-tamper")
    path = os.path.join(settings.evidence_dir, f"{eng_id}/{run_id}/garak.report.jsonl")
    blob = bytearray(open(path, "rb").read())
    blob[-1] ^= 0x01
    os.chmod(path, 0o640)
    with open(path, "wb") as fh:
        fh.write(bytes(blob))

    r = client.get(
        f"/api/engagements/{eng_id}/evidence/{entry['evidence_id']}/content", headers=OWNER
    )
    assert r.status_code == 409
    assert "integrity" in r.json()["detail"]
    [failed] = _audit(db, eng_id, "evidence.integrity_failed")
    assert failed["evidence_id"] == entry["evidence_id"]
    assert _audit(db, eng_id, "evidence.downloaded") == []


def test_a_container_run_without_an_evidence_key_fails_before_sealing(env):
    from khandaq import worker

    client, db, settings = env
    eng_id, tid = _engagement(client, "no-key")
    run = _queue(client, eng_id, tid)
    previous, settings.evidence_key = settings.evidence_key, ""
    try:
        worker.drain(db, runner=FakeRunner())
    finally:
        settings.evidence_key = previous
    after = _run(client, eng_id, run["id"])
    assert after["state"] == "failed"
    assert "KHANDAQ_EVIDENCE_KEY" in after["reject_reason"]
    assert client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()["entries"] == []


def test_an_unreachable_evidence_store_is_a_503_not_a_crash(env, monkeypatch):
    """Found by the deployment smoke script (spec 019): a store outage surfaced as a 500."""
    from khandaq.evidence_store import EvidenceStoreError
    from khandaq.routers import evidence as evidence_router

    client, db, _ = env
    eng_id, _, entry = _executed_run(client, db, "download-store-down")

    class DownStore:
        def get(self, object_key):
            raise EvidenceStoreError("object store get failed: EndpointConnectionError")

    monkeypatch.setattr(evidence_router, "store_from_settings", lambda settings: DownStore())
    r = client.get(
        f"/api/engagements/{eng_id}/evidence/{entry['evidence_id']}/content", headers=OWNER
    )
    assert r.status_code == 503
    assert r.json()["detail"] == "evidence store unavailable; try again later"
    assert _audit(db, eng_id, "evidence.downloaded") == []
