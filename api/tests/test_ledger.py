"""Integration tests for the evidence ledger (spec 004).

Requires a real PostgreSQL and the khandaq_core wheel; skips without KHANDAQ_TEST_DATABASE_URL.
Evidence is sealed via the ledger service (the run path will call the same service in spec 005).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, update
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

OWNER = {"X-Khandaq-Dev-User": "owner@test"}


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


def _engagement_with_run(client, eng, name):
    from khandaq import models as m

    eng_id = client.post("/api/engagements", json={"name": name}, headers=OWNER).json()["id"]
    with Session(eng) as s:
        run = m.Run(engagement_id=eng_id, adapter="echo", state="succeeded")
        s.add(run)
        s.commit()
        run_id = run.id
    return eng_id, run_id


def test_seal_and_verify_chain(ctx):
    client, eng = ctx
    from khandaq import ledger as ledger_svc

    eng_id, run_id = _engagement_with_run(client, eng, "ledger-ok")
    with Session(eng) as s:
        for i in range(3):
            ledger_svc.seal_evidence(
                s,
                engagement_id=eng_id,
                run_id=run_id,
                kind="raw",
                object_key=f"k{i}",
                sha256=f"sha256:{i * 11:064x}",
            )
        s.commit()

    r = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER)
    body = r.json()
    assert r.status_code == 200
    assert len(body["entries"]) == 3
    assert body["entries"][0]["seq"] == 1 and body["entries"][0]["prev_hash"] is None
    assert body["root"] == body["entries"][-1]["entry_hash"]
    assert body["verify"]["ok"] is True

    # Verify chaining is real: each entry links to the previous entry_hash.
    for prev, cur in zip(body["entries"], body["entries"][1:], strict=False):
        assert cur["prev_hash"] == prev["entry_hash"]


def test_tampering_is_detected(ctx):
    client, eng = ctx
    from khandaq import ledger as ledger_svc
    from khandaq import models as m

    eng_id, run_id = _engagement_with_run(client, eng, "ledger-tamper")
    with Session(eng) as s:
        for i in range(3):
            ledger_svc.seal_evidence(
                s,
                engagement_id=eng_id,
                run_id=run_id,
                kind="raw",
                object_key=f"k{i}",
                sha256=f"sha256:{i * 7:064x}",
            )
        s.commit()
        # Tamper: flip the stored entry_hash of seq 2.
        s.execute(
            update(m.LedgerEntry)
            .where(m.LedgerEntry.engagement_id == eng_id, m.LedgerEntry.seq == 2)
            .values(entry_hash="sha256:tampered")
        )
        s.commit()

    r = client.post(f"/api/engagements/{eng_id}/ledger/verify", headers=OWNER)
    body = r.json()
    assert body["ok"] is False
    assert body["broken_at"] == 2
