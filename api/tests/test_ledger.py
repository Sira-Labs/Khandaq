"""Integration tests for the evidence ledger (spec 004).

Requires a real PostgreSQL and the khandaq_core wheel; skips without KHANDAQ_TEST_DATABASE_URL.
Evidence is sealed via the ledger service (the run path will call the same service in spec 005).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, update
from sqlalchemy.exc import DBAPIError
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

        tamper = (
            update(m.LedgerEntry)
            .where(m.LedgerEntry.engagement_id == eng_id, m.LedgerEntry.seq == 2)
            .values(entry_hash="sha256:tampered")
        )
        # Layer 1: the table is append-only, so an ordinary UPDATE is refused outright.
        with pytest.raises(DBAPIError, match="append-only"):
            s.execute(tamper)
        s.rollback()

        # Layer 2: an owner who disables the trigger can rewrite a row — the chain still shows it.
        s.execute(
            text("ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_update_delete")
        )
        s.execute(tamper)
        s.execute(text("ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_no_update_delete"))
        s.commit()

    r = client.post(f"/api/engagements/{eng_id}/ledger/verify", headers=OWNER)
    body = r.json()
    assert body["ok"] is False
    assert body["broken_at"] == 2


def test_concurrent_seals_queue_instead_of_failing(ctx):
    """Two runs sealing at once used to compute the same seq; the loser's transaction failed."""
    import threading

    client, eng = ctx
    from khandaq import ledger as ledger_svc

    eng_id, run_id = _engagement_with_run(client, eng, "ledger-race")
    seal = dict(engagement_id=eng_id, run_id=run_id, kind="raw")
    first, second = Session(eng), Session(eng)
    outcome: dict = {}

    def seal_second():
        try:
            ledger_svc.seal_evidence(second, object_key="b", sha256=f"sha256:{2:064x}", **seal)
            second.commit()
            outcome["ok"] = True
        except DBAPIError as exc:  # pragma: no cover - the bug this test guards against
            outcome["error"] = exc

    try:
        ledger_svc.seal_evidence(first, object_key="a", sha256=f"sha256:{1:064x}", **seal)
        worker = threading.Thread(target=seal_second)
        worker.start()
        worker.join(0.5)
        assert worker.is_alive(), "the second seal should wait for the first transaction"
        first.commit()
        worker.join(10)
    finally:
        first.close()
        second.close()

    assert outcome == {"ok": True}
    with Session(eng) as s:
        status = ledger_svc.chain_status(s, eng_id)
    assert status["verify"]["ok"] and [e["seq"] for e in status["entries"]] == [1, 2]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM evidence",
        "UPDATE evidence SET object_key = 'swapped'",
        "DELETE FROM ledger_entries",
        "TRUNCATE evidence CASCADE",
        "TRUNCATE ledger_entries",
        "TRUNCATE audit_log",
    ],
)
def test_evidence_ledger_and_audit_are_append_only(ctx, sql):
    _, eng = ctx
    with pytest.raises(DBAPIError, match="append-only"):
        with eng.begin() as conn:
            conn.execute(text(sql))


# --- ADR-0014: format-2 entries seal the evidence row's metadata --------------------------------


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("object_key", "'someone-elses/evidence.json'"),
        ("kind", "'artefact'"),
        ("bytes", "999"),
        ("redacted", "true"),
        ("run_id", None),  # moved to another run of the same engagement
    ],
)
def test_relabelling_sealed_evidence_breaks_the_chain(ctx, column, value):
    """The ledger used to seal only the artefact's sha256, so an owner who disabled the trigger
    could move or relabel evidence without the chain noticing."""
    client, eng = ctx
    from khandaq import ledger as ledger_svc
    from khandaq import models as m

    eng_id, run_id = _engagement_with_run(client, eng, f"ledger-relabel-{column}")
    with Session(eng) as s:
        evidence_ids = []
        for i in range(3):
            ev, row = ledger_svc.seal_evidence(
                s,
                engagement_id=eng_id,
                run_id=run_id,
                kind="raw",
                object_key=f"{eng_id}/{run_id}/k{i}",
                sha256=f"sha256:{i + 1:064x}",
            )
            assert row.format == 2
            evidence_ids.append(ev.id)
        other_run = m.Run(engagement_id=eng_id, adapter="echo", state="succeeded")
        s.add(other_run)
        s.commit()
        new_value = value if value is not None else f"'{other_run.id}'"

        assert ledger_svc.verify_chain(s, eng_id)["ok"] is True
        s.execute(text("ALTER TABLE evidence DISABLE TRIGGER evidence_no_update_delete"))
        s.execute(
            text(f"UPDATE evidence SET {column} = {new_value} WHERE id = :i"),
            {"i": evidence_ids[1]},
        )
        s.execute(text("ALTER TABLE evidence ENABLE TRIGGER evidence_no_update_delete"))
        s.commit()

    body = client.post(f"/api/engagements/{eng_id}/ledger/verify", headers=OWNER).json()
    assert body["ok"] is False and body["broken_at"] == 2, body


def test_ledger_entries_report_their_format(ctx):
    client, eng = ctx
    from khandaq import ledger as ledger_svc

    eng_id, run_id = _engagement_with_run(client, eng, "ledger-format")
    with Session(eng) as s:
        ledger_svc.seal_evidence(
            s,
            engagement_id=eng_id,
            run_id=run_id,
            kind="raw",
            object_key="k",
            sha256=f"sha256:{5:064x}",
        )
        s.commit()
    entries = client.get(f"/api/engagements/{eng_id}/ledger", headers=OWNER).json()["entries"]
    assert [e["format"] for e in entries] == [2]
    assert entries[0]["evidence_hash"] != f"sha256:{5:064x}"  # the record, not the bytes alone
