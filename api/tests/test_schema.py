"""Schema and migration tests (spec 001).

These require a real PostgreSQL (the DB-level invariants — trigger, composite FK, unique — cannot
be exercised otherwise). They run in CI against the `postgres` service and skip locally when
KHANDAQ_TEST_DATABASE_URL is unset.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")

EXPECTED_TABLES = {
    "users",
    "api_tokens",
    "engagements",
    "engagement_members",
    "targets",
    "scopes",
    "suites",
    "runs",
    "findings",
    "evidence",
    "ledger_entries",
    "audit_log",
    "alembic_version",
}


@pytest.fixture(scope="module")
def engine():
    from khandaq import migrate

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:  # clean slate, then migrate up
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)
    yield eng
    eng.dispose()


def _seed_user_and_engagement(session: Session, suffix: str):
    from khandaq import models as m

    user = m.User(email=f"owner-{suffix}@example.test", org_role="member")
    session.add(user)
    session.flush()
    eng = m.Engagement(name=f"eng-{suffix}", owner_user_id=user.id, state="active")
    session.add(eng)
    session.flush()
    run = m.Run(engagement_id=eng.id, adapter="echo", state="succeeded")
    session.add(run)
    session.flush()
    return user, eng, run


def test_all_tables_created(engine) -> None:
    tables = set(inspect(engine).get_table_names())
    missing = EXPECTED_TABLES - tables
    assert not missing, f"missing tables: {missing}"


def test_version_reports_revision(engine) -> None:
    from khandaq.db import schema_revision
    from khandaq.settings import Settings

    assert schema_revision(Settings(database_url=TEST_URL)) == "0001_initial"


def test_audit_log_is_append_only(engine) -> None:
    from khandaq import models as m

    with Session(engine) as s:
        s.add(m.AuditLog(action="test.event", detail={"k": "v"}))
        s.commit()

    # UPDATE must be rejected by the trigger.
    with pytest.raises(DBAPIError):
        with engine.begin() as conn:
            conn.execute(text("UPDATE audit_log SET action = 'tampered'"))

    # DELETE must be rejected too.
    with pytest.raises(DBAPIError):
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM audit_log"))


def test_dedup_of_cannot_cross_engagements(engine) -> None:
    from khandaq import models as m

    with Session(engine) as s:
        _, eng_a, run_a = _seed_user_and_engagement(s, "a")
        _, eng_b, run_b = _seed_user_and_engagement(s, "b")
        canonical = m.Finding(
            engagement_id=eng_a.id,
            run_id=run_a.id,
            fingerprint="sha256:aaa",
            severity="high",
            body={"schema": "khandaq.finding/1"},
        )
        s.add(canonical)
        s.commit()
        canonical_id = canonical.id

        # A finding in engagement B pointing at engagement A's finding must be rejected.
        bad = m.Finding(
            engagement_id=eng_b.id,
            run_id=run_b.id,
            fingerprint="sha256:bbb",
            severity="high",
            body={},
            dedup_of=canonical_id,
        )
        s.add(bad)
        with pytest.raises(IntegrityError):
            s.commit()


def test_ledger_seq_unique_per_engagement(engine) -> None:
    from khandaq import models as m

    with Session(engine) as s:
        _, eng, run = _seed_user_and_engagement(s, "ledger")
        ev = m.Evidence(
            engagement_id=eng.id,
            run_id=run.id,
            kind="raw",
            object_key="k1",
            sha256="x",
        )
        s.add(ev)
        s.flush()
        s.add(m.LedgerEntry(engagement_id=eng.id, seq=1, evidence_id=ev.id, entry_hash="h1"))
        s.add(m.LedgerEntry(engagement_id=eng.id, seq=1, evidence_id=ev.id, entry_hash="h2"))
        with pytest.raises(IntegrityError):
            s.commit()
