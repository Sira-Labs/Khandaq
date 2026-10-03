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

    migrate.upgrade(url=TEST_URL, revision="0003_append_only")  # the boot that must not fail

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


# --- 0004: fingerprint recipe v2 (ADR-0013) ------------------------------------------------------

# Values the core produced under the v1 recipe (computed with the pre-ADR-0013 wheel), so the
# downgrade's Python v1 recipe is pinned against the real old implementation.
_V1_PINNED = {
    "mapped": "sha256:d0ff90d4025381e128a6fcdb13b32361703c30cfc254a6cd4e849970d4df2cbe",
    "unmapped": "sha256:46fa20a57c85690a2ed7a3ec2595a84733411ae831a2a47b75ba74e85b4638a6",
}


def _v1_pin_body(mapped: bool) -> dict:
    mappings = [
        {"framework": "owasp-llm-2026", "id": "LLM01"},
        {"framework": "atlas", "id": "AML.T0051"},
        {"framework": "atlas", "id": "AML.T0051"},
    ]
    return {
        "schema": "khandaq.finding/1",
        "engagement_id": "e",
        "run_id": "r1",
        "rule_id": "garak.promptinject.hijack",
        "severity": "high",
        "source": {"tool": "garak", "version": "0.17.0"},
        "target_ref": "tgt_\u00fc",
        "locations": (
            [{"logicalLocations": [{"fullyQualifiedName": "probe \u00fc"}]}] if mapped else []
        ),
        "x-khandaq": {"phase": "04", "mappings": mappings if mapped else [], "evidence": []},
    }


def _load_0004():
    import importlib

    return importlib.import_module("khandaq.migrations.versions.0004_fingerprint_v2")


def test_0004_downgrade_recipe_matches_the_old_core():
    m = _load_0004()
    assert m._v1(_v1_pin_body(True)) == _V1_PINNED["mapped"]
    assert m._v1(_v1_pin_body(False)) == _V1_PINNED["unmapped"]


def _finding(rule: str, run: str, mappings: list[tuple[str, str]], evidence: list[str], **extra):
    xk = {
        "phase": "04-prompt-injection",
        "mappings": [{"framework": f, "id": i} for f, i in mappings],
        "evidence": evidence,
        **extra,
    }
    return {
        "schema": "khandaq.finding/1",
        "engagement_id": "e",
        "run_id": run,
        "rule_id": rule,
        "severity": "high",
        "source": {"tool": "garak", "version": "0.17.0"},
        "target_ref": "t",
        "locations": [{"logicalLocations": [{"fullyQualifiedName": rule}]}],
        "x-khandaq": xk,
    }


def test_0004_refingerprints_and_rebuilds_dedup_links():
    import khandaq_core as kc

    from khandaq import migrate

    m = _load_0004()
    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)
    migrate.downgrade(url=TEST_URL, revision="0003_append_only")  # a v1 install

    llm01 = [("owasp-llm-2026", "LLM01")]
    llm02 = [("owasp-llm-2026", "LLM02")]
    llm02_curated = [("owasp-llm-2025", "LLM02"), ("owasp-llm-2026", "LLM02")]
    # Same location for the split pair, so v1 (mappings + target + location) really merged them.
    hijack = _finding("garak.promptinject.hijack", "r1", llm01, ["ev1", "ev2"])
    dan = _finding("garak.dan.dan_11", "r2", llm01, ["ev2"])
    dan["locations"] = hijack["locations"]
    rows = [
        # split: v1 merged two distinct rules because they shared a mapping set
        ("a0", "r1", "2026-01-01", True, None, "open", hijack),
        ("a1", "r2", "2026-01-02", False, "a0", "open", dan),
        # merge: one issue, re-fingerprinted under v1 by a mapping edit; the later row was triaged
        (
            "b0",
            "r1",
            "2026-01-01",
            True,
            None,
            "open",
            _finding("garak.leakreplay", "r1", llm02, ["ev4"]),
        ),
        (
            "b1",
            "r2",
            "2026-01-02",
            True,
            None,
            "accepted_risk",
            _finding("garak.leakreplay", "r2", llm02_curated, ["ev5"]),
        ),
        # unchanged: a group v2 agrees with; its body is left exactly as it was
        (
            "c0",
            "r1",
            "2026-01-01",
            True,
            None,
            "open",
            _finding("garak.xss", "r1", [], ["ev6", "ev7"], also_found_by=["pyrit"]),
        ),
        ("c1", "r2", "2026-01-02", False, "c0", "open", _finding("garak.xss", "r2", [], ["ev7"])),
    ]
    evidence = [
        ("ev1", "r1"),
        ("ev2", "r2"),
        ("ev4", "r1"),
        ("ev5", "r2"),
        ("ev6", "r1"),
        ("ev7", "r2"),
    ]
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email) VALUES ('u', 'u@test')"))
        conn.execute(
            text("INSERT INTO engagements (id, name, owner_user_id) VALUES ('e', 'x', 'u')")
        )
        for run in ("r1", "r2"):
            conn.execute(
                text("INSERT INTO runs (id, engagement_id, adapter) VALUES (:r, 'e', 'garak')"),
                {"r": run},
            )
        for eid, run in evidence:
            conn.execute(
                text(
                    "INSERT INTO evidence (id, engagement_id, run_id, kind, object_key, sha256) "
                    "VALUES (:i, 'e', :r, 'transcript', :k, :h)"
                ),
                {"i": eid, "r": run, "k": f"e/{run}/{eid}", "h": "sha256:" + "0" * 64},
            )
        for fid, run, ts, canonical, dedup_of, status, body in rows:
            conn.execute(
                text(
                    "INSERT INTO findings (id, engagement_id, run_id, fingerprint, canonical, "
                    "dedup_of, status, severity, body, created_at) VALUES (:i, 'e', :r, :fp, :c, "
                    ":d, :s, 'high', CAST(:b AS jsonb), :ts)"
                ),
                {
                    "i": fid,
                    "r": run,
                    "fp": m._v1(body),
                    "c": canonical,
                    "d": dedup_of,
                    "s": status,
                    "b": json.dumps(body),
                    "ts": ts,
                },
            )
    before_c0 = rows[4][6]

    migrate.upgrade(url=TEST_URL, revision="0004_fingerprint_v2")

    with eng.connect() as conn:
        found = {
            r.id: r
            for r in conn.execute(
                text("SELECT id, fingerprint, canonical, dedup_of, status, body FROM findings")
            ).all()
        }
        audit = (
            conn.execute(
                text("SELECT detail FROM audit_log WHERE action = 'findings.refingerprinted'")
            )
            .scalars()
            .all()
        )
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        index = conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'uq_findings_canonical_fingerprint'"
            )
        ).scalar()

    assert revision == "0004_fingerprint_v2"
    assert index is not None and "WHERE canonical" in index
    for row in found.values():
        assert row.fingerprint == kc.fingerprint(json.dumps(row.body)) == row.body["fingerprint"]
        assert row.body["schema"] == "khandaq.finding/2"

    # split: both rules are canonical again, each with only the evidence of its own run
    assert found["a0"].canonical and found["a1"].canonical and found["a1"].dedup_of is None
    assert found["a0"].body["x-khandaq"]["evidence"] == ["ev1"]
    assert found["a1"].body["x-khandaq"]["evidence"] == ["ev2"]

    # merge: the earliest row is canonical, holds both runs' evidence, and keeps the triage
    assert found["b0"].canonical and not found["b1"].canonical
    assert found["b1"].dedup_of == "b0"
    assert found["b0"].body["x-khandaq"]["evidence"] == ["ev4", "ev5"]
    assert found["b0"].status == "accepted_risk"

    # unchanged: the body is as it was, apart from fingerprint and schema id
    c0 = dict(found["c0"].body)
    assert found["c0"].canonical and found["c1"].dedup_of == "c0"
    assert {k: v for k, v in c0.items() if k not in ("fingerprint", "schema")} == {
        k: v for k, v in before_c0.items() if k != "schema"
    }

    assert len(audit) == 1
    assert audit[0]["canonical_before"] == 4 and audit[0]["canonical_after"] == 4
    assert audit[0]["groups_regrouped"] == 3  # a0, a1 (split) and b0 (merge)

    # Downgrade restores the v1 recipe and its grouping.
    migrate.downgrade(url=TEST_URL, revision="0003_append_only")
    with eng.connect() as conn:
        back = {
            r.id: r
            for r in conn.execute(
                text("SELECT id, fingerprint, canonical, dedup_of, body FROM findings")
            ).all()
        }
    eng.dispose()
    for row in back.values():
        assert row.fingerprint == m._v1(row.body)
        assert row.body["schema"] == "khandaq.finding/1"
    assert back["a1"].dedup_of == "a0" and back["c1"].dedup_of == "c0"
    assert back["b0"].canonical and back["b1"].canonical


# --- 0005: ledger entry format (ADR-0014) ---------------------------------------------------------


def _v1_entry_hash(seq: int, evidence_hash: str, prev_hash: str | None) -> str:
    """The format-1 entry hash, as the pre-ADR-0014 core computed it."""
    import hashlib

    data = f"{seq}\0{evidence_hash}\0{prev_hash or ''}".encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_0005_keeps_existing_chains_verifiable_and_refuses_downgrade_after_use():
    from sqlalchemy.orm import Session

    from khandaq import ledger as ledger_svc
    from khandaq import migrate

    eng = create_engine(TEST_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url=TEST_URL)
    migrate.downgrade(url=TEST_URL, revision="0004_fingerprint_v2")  # a pre-ADR-0014 install

    with eng.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email) VALUES ('u', 'u@test')"))
        conn.execute(
            text("INSERT INTO engagements (id, name, owner_user_id) VALUES ('e', 'x', 'u')")
        )
        conn.execute(
            text("INSERT INTO runs (id, engagement_id, adapter) VALUES ('r', 'e', 'echo')")
        )
        prev = None
        for seq in (1, 2):
            sha = f"sha256:{seq:064x}"
            entry = _v1_entry_hash(seq, sha, prev)
            conn.execute(
                text(
                    "INSERT INTO evidence (id, engagement_id, run_id, kind, object_key, sha256) "
                    "VALUES (:i, 'e', 'r', 'raw', :k, :s)"
                ),
                {"i": f"ev{seq}", "k": f"e/r/{seq}", "s": sha},
            )
            conn.execute(
                text(
                    "INSERT INTO ledger_entries (id, engagement_id, seq, evidence_id, entry_hash, "
                    "prev_hash) VALUES (:i, 'e', :q, :ev, :h, :p)"
                ),
                {"i": f"led{seq}", "q": seq, "ev": f"ev{seq}", "h": entry, "p": prev},
            )
            prev = entry

    migrate.upgrade(url=TEST_URL)

    with Session(eng) as s:
        status = ledger_svc.chain_status(s, "e")
        assert status["verify"]["ok"] is True, status["verify"]
        assert [e["format"] for e in status["entries"]] == [1, 1]
        ledger_svc.seal_evidence(
            s,
            engagement_id="e",
            run_id="r",
            kind="raw",
            object_key="e/r/3",
            sha256=f"sha256:{3:064x}",
        )
        s.commit()
        status = ledger_svc.chain_status(s, "e")
        assert status["verify"]["ok"] is True, status["verify"]
        assert [e["format"] for e in status["entries"]] == [1, 1, 2]

    with pytest.raises(RuntimeError, match="format 2"):
        migrate.downgrade(url=TEST_URL, revision="0004_fingerprint_v2")
    eng.dispose()
