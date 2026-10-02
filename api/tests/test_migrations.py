"""Upgrading an install that predates migration 0003 (code review).

Dedup used to run only within one run, so existing databases can hold several canonical findings
with the same fingerprint. 0003 must link them to the earliest, keep every piece of evidence and
tool attribution visible on that row, and build its unique index — never fail the boot.
"""

from __future__ import annotations

import json
import os

import pytest
from sqlalchemy import create_engine, text

TEST_URL = os.environ.get("KHANDAQ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="KHANDAQ_TEST_DATABASE_URL not set")


def _body(tool: str, evidence: list[str], also: list[str] | None = None) -> str:
    xk: dict = {"evidence": evidence}
    if also is not None:
        xk["also_found_by"] = also
    return json.dumps({"source": {"tool": tool}, "x-khandaq": xk})


def test_0003_merges_and_links_pre_existing_duplicates():
    from khandaq import migrate

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)
    migrate.downgrade(url=TEST_URL, revision="0002_sessions")  # a pre-review install

    rows = [  # (id, run, created_at, body): three sightings of one issue, one unrelated finding
        ("f0", "r1", "2026-01-01", _body("garak", ["ev_a"])),
        ("f1", "r2", "2026-01-02", _body("pyrit", ["ev_b", "ev_a"])),
        ("f2", "r3", "2026-01-03", _body("garak", ["ev_c"], also=["promptfoo"])),
        ("g0", "r1", "2026-01-01", _body("garak", ["ev_z"])),
    ]
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email) VALUES ('u', 'u@test')"))
        conn.execute(
            text("INSERT INTO engagements (id, name, owner_user_id) VALUES ('e', 'x', 'u')")
        )
        for run in ("r1", "r2", "r3"):
            conn.execute(
                text("INSERT INTO runs (id, engagement_id, adapter) VALUES (:r, 'e', 'echo')"),
                {"r": run},
            )
        for fid, run, ts, body in rows:
            conn.execute(
                text(
                    "INSERT INTO findings (id, engagement_id, run_id, fingerprint, canonical, "
                    "severity, body, created_at) VALUES (:i, 'e', :r, :fp, true, 'high', "
                    "CAST(:b AS jsonb), :ts)"
                ),
                {
                    "i": fid,
                    "r": run,
                    "fp": "fp1" if fid.startswith("f") else "fp2",
                    "b": body,
                    "ts": ts,
                },
            )

    migrate.upgrade(url=TEST_URL)  # the boot that must not fail

    with eng.connect() as conn:
        found = {
            r.id: r
            for r in conn.execute(text("SELECT id, canonical, dedup_of, body FROM findings")).all()
        }
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    eng.dispose()

    assert revision == "0003_append_only"
    assert found["f0"].canonical and not found["f1"].canonical and not found["f2"].canonical
    assert found["f1"].dedup_of == found["f2"].dedup_of == "f0"
    kept = found["f0"].body["x-khandaq"]
    assert sorted(kept["evidence"]) == ["ev_a", "ev_b", "ev_c"]  # nothing vanished from the views
    assert sorted(kept["also_found_by"]) == ["promptfoo", "pyrit"]  # not garak: it is the source
    # A finding without duplicates is left exactly as it was.
    assert found["g0"].canonical and found["g0"].body["x-khandaq"] == {"evidence": ["ev_z"]}
