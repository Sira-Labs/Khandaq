"""Fingerprint recipe v2: framework mappings are no longer identity (ADR-0013).

Every stored finding is re-fingerprinted from its ``body`` with the core's current recipe
(``khandaq.finding/2``), and the cross-run dedup links are rebuilt under it, per engagement:

- In each new fingerprint group the earliest row (``created_at``, ``id``) is canonical and every
  other row links to it through ``dedup_of`` — the same rule 0003 and the run path use.
- A group whose membership and canonical row are unchanged (the common case) keeps its rows
  exactly as they were, apart from the new fingerprint and schema id.
- A group that changed (v1 merged two rules that shared a mapping set, or a mapping edit had split
  one issue) gets its canonical row's attribution recomputed from the members' **own**
  contributions: evidence sealed in the member's own run (``evidence.run_id``), and the tools the
  member itself recorded (its ``source`` and in-run ``x-khandaq.sources``). Evidence and tools a
  former canonical had absorbed from rows that now belong to another group are not carried over.
- Triage survives a merge: an ``open`` canonical takes the status of the earliest member that was
  canonical before and had been triaged.
- One ``findings.refingerprinted`` audit entry per engagement records the change.

A body that no longer validates stops the migration: mixing two recipes in one table would make
dedup silently wrong. Downgrade recomputes the v1 recipe the same way.

Revision ID: 0004_fingerprint_v2
Revises: 0003_append_only
Create Date: 2026-10-03
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

import khandaq_core as kc
from alembic import op
from sqlalchemy import text
from sqlalchemy.engine import Connection

from khandaq.models import new_id

revision = "0004_fingerprint_v2"
down_revision = "0003_append_only"
branch_labels = None
depends_on = None

_V1_SCHEMA = "khandaq.finding/1"
_V2_SCHEMA = "khandaq.finding/2"

Recipe = Callable[[dict], str]


def _v2(body: dict) -> str:
    return kc.fingerprint(json.dumps(body))


def _canonical_json(value: Any) -> str:
    # serde_json's default output: sorted keys, no whitespace, UTF-8 unescaped.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _v1(body: dict) -> str:
    """The pre-ADR-0013 recipe, kept only for downgrade (tests pin it against the old core)."""
    xk = body.get("x-khandaq") or {}
    identity = sorted({f"{m['framework']}:{m['id']}" for m in xk.get("mappings") or []})
    if not identity:
        identity = [f"rule:{body['rule_id']}"]
    locations = body.get("locations") or []
    payload = {
        "identity": identity,
        "target": body.get("target_ref") or "",
        "location": _canonical_json(locations) if locations else "",
    }
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode()).hexdigest()


def _own_evidence(row: dict, evidence_run: dict[str, str]) -> list[str]:
    """Evidence the row contributed itself: everything except ids sealed in another run."""
    xk = row["body"].get("x-khandaq") or {}
    return [
        e for e in xk.get("evidence") or [] if evidence_run.get(e, row["run_id"]) == row["run_id"]
    ]


def _own_tools(row: dict, absorbed: bool) -> set[str]:
    """Tools the row recorded itself. A former canonical that absorbed other runs' rows has their
    tools folded into ``also_found_by``; its in-run tools are in ``source`` and ``sources``."""
    body = row["body"]
    xk = body.get("x-khandaq") or {}
    tools = {(body.get("source") or {}).get("tool")}
    tools |= {s.get("tool") for s in xk.get("sources") or []}
    if not absorbed:
        tools |= set(xk.get("also_found_by") or [])
    return {t for t in tools if t}


def _regroup(conn: Connection, recipe: Recipe, schema_id: str) -> None:
    engagements = conn.execute(text("SELECT DISTINCT engagement_id FROM findings")).scalars().all()
    for engagement_id in engagements:
        _regroup_engagement(conn, engagement_id, recipe, schema_id)


def _regroup_engagement(
    conn: Connection, engagement_id: str, recipe: Recipe, schema_id: str
) -> None:
    rows = [
        dict(r)
        for r in conn.execute(
            text(
                "SELECT id, run_id, canonical, dedup_of, status, body FROM findings "
                "WHERE engagement_id = :e ORDER BY created_at, id"
            ),
            {"e": engagement_id},
        ).mappings()
    ]
    evidence_run: dict[str, str] = {
        r.id: r.run_id
        for r in conn.execute(
            text("SELECT id, run_id FROM evidence WHERE engagement_id = :e"), {"e": engagement_id}
        )
    }

    old_group = {r["id"]: r["id"] if r["canonical"] else r["dedup_of"] for r in rows}
    old_members: dict[str, set[str]] = {}
    for fid, key in old_group.items():
        old_members.setdefault(key, set()).add(fid)
    absorbed = {key for key, members in old_members.items() if len(members) > 1}

    new_groups: dict[str, list[dict]] = {}
    for row in rows:  # already in (created_at, id) order
        try:
            fp = recipe(row["body"])
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(
                f"finding {row['id']} (engagement {engagement_id}) cannot be re-fingerprinted: "
                f"{exc}. Fix or remove the row, then re-run the migration."
            ) from exc
        new_groups.setdefault(fp, []).append(row)

    regrouped = 0
    for fp, members in new_groups.items():
        keeper = members[0]
        ids = {m["id"] for m in members}
        unchanged = keeper["canonical"] and old_members.get(keeper["id"]) == ids
        for m in members:
            m["body"]["fingerprint"] = fp
            m["body"]["schema"] = schema_id
        if not unchanged:
            regrouped += 1
            _recompute_keeper(keeper, members, evidence_run, absorbed)
        for m in members:
            is_keeper = m is keeper
            conn.execute(
                text(
                    "UPDATE findings SET fingerprint = :fp, canonical = :c, dedup_of = :d, "
                    "status = :s, body = CAST(:b AS jsonb) WHERE id = :i"
                ),
                {
                    "fp": fp,
                    "c": is_keeper,
                    "d": None if is_keeper else keeper["id"],
                    "s": m["status"],
                    "b": json.dumps(m["body"]),
                    "i": m["id"],
                },
            )

    conn.execute(
        text(
            "INSERT INTO audit_log (id, action, engagement_id, detail) "
            "VALUES (:i, 'findings.refingerprinted', :e, CAST(:d AS jsonb))"
        ),
        {
            "i": new_id("aud"),
            "e": engagement_id,
            "d": json.dumps(
                {
                    "migration": revision,
                    "schema": schema_id,
                    "findings": len(rows),
                    "canonical_before": len(old_members),
                    "canonical_after": len(new_groups),
                    "groups_regrouped": regrouped,
                }
            ),
        },
    )


def _recompute_keeper(
    keeper: dict, members: list[dict], evidence_run: dict[str, str], absorbed: set[str]
) -> None:
    evidence: list[str] = []
    tools: set[str] = set()
    for m in members:
        for e in _own_evidence(m, evidence_run):
            if e not in evidence:
                evidence.append(e)
        tools |= _own_tools(m, absorbed=m["id"] in absorbed)
    own_tool = (keeper["body"].get("source") or {}).get("tool")
    xk = keeper["body"].setdefault("x-khandaq", {})
    xk["evidence"] = evidence
    xk["also_found_by"] = sorted(tools - {own_tool})
    if keeper["status"] == "open":
        triaged = next(
            (m["status"] for m in members if m["canonical"] and m["status"] != "open"), None
        )
        if triaged is not None:
            keeper["status"] = triaged


def _run(recipe: Recipe, schema_id: str) -> None:
    # Rows change fingerprint one at a time; the one-canonical-per-fingerprint index would reject
    # the intermediate states, so it is rebuilt once the table is consistent again.
    op.execute("DROP INDEX IF EXISTS uq_findings_canonical_fingerprint")
    _regroup(op.get_bind(), recipe, schema_id)
    op.execute(
        "CREATE UNIQUE INDEX uq_findings_canonical_fingerprint "
        "ON findings (engagement_id, fingerprint) WHERE canonical"
    )


def upgrade() -> None:
    _run(_v2, _V2_SCHEMA)


def downgrade() -> None:
    _run(_v1, _V1_SCHEMA)
