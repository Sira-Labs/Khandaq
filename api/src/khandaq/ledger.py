"""Evidence ledger service (spec 004).

Seals evidence into the append-only, hash-chained ledger and verifies the chain, delegating the
hashing to the Rust core via the `khandaq_core` wheel (ADR-0007/0011). The core LedgerEntry model is
{seq, evidence_hash, prev_hash, entry_hash}; in the database the entry references an Evidence row,
and `evidence_hash` is that row's sha256.
"""

from __future__ import annotations

import json

import khandaq_core as kc
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import Evidence, LedgerEntry


def lock_engagement(session: Session, engagement_id: str) -> None:
    """Serialise ledger appends (and cross-run dedup) per engagement until the transaction ends.

    Two runs sealing evidence at once would otherwise both read the same last entry and compute the
    same next ``seq``; the unique constraint stops a fork, but the loser's whole transaction failed.
    A transaction-scoped advisory lock makes the second wait instead (re-entrant per transaction).
    """
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:eid, 0))"), {"eid": engagement_id}
    )


def _core_entry(row: LedgerEntry, sha256: str) -> dict:
    return {
        "seq": row.seq,
        "evidence_hash": sha256,
        "prev_hash": row.prev_hash,
        "entry_hash": row.entry_hash,
    }


def _last_entry(session: Session, engagement_id: str) -> LedgerEntry | None:
    return session.scalars(
        select(LedgerEntry)
        .where(LedgerEntry.engagement_id == engagement_id)
        .order_by(LedgerEntry.seq.desc())
        .limit(1)
    ).first()


def seal_evidence(
    session: Session,
    *,
    engagement_id: str,
    run_id: str,
    kind: str,
    object_key: str,
    sha256: str,
    bytes_: int = 0,
    redacted: bool = False,
) -> tuple[Evidence, LedgerEntry]:
    """Store an Evidence row and append it to the engagement's hash chain. Caller commits."""
    lock_engagement(session, engagement_id)
    evidence = Evidence(
        engagement_id=engagement_id,
        run_id=run_id,
        kind=kind,
        object_key=object_key,
        sha256=sha256,
        bytes=bytes_,
        redacted=redacted,
    )
    session.add(evidence)
    session.flush()  # assign evidence.id

    last = _last_entry(session, engagement_id)
    prev_json = None
    if last is not None:
        prev_ev = session.get(Evidence, last.evidence_id)
        prev_sha = prev_ev.sha256 if prev_ev else ""
        prev_json = json.dumps(_core_entry(last, prev_sha))
    entry = json.loads(kc.ledger_append(prev_json, sha256))

    row = LedgerEntry(
        engagement_id=engagement_id,
        seq=entry["seq"],
        evidence_id=evidence.id,
        entry_hash=entry["entry_hash"],
        prev_hash=entry["prev_hash"],
    )
    session.add(row)
    session.flush()
    return evidence, row


_CORE_KEYS = ("seq", "evidence_hash", "prev_hash", "entry_hash")


def load_chain(session: Session, engagement_id: str) -> list[dict]:
    """Return the chain as core LedgerEntry dicts (ordered by seq), each with its evidence_id.

    One joined query (it used to issue one evidence lookup per entry)."""
    rows = session.execute(
        select(LedgerEntry, Evidence.sha256)
        .outerjoin(Evidence, Evidence.id == LedgerEntry.evidence_id)
        .where(LedgerEntry.engagement_id == engagement_id)
        .order_by(LedgerEntry.seq.asc())
    ).all()
    chain = []
    for row, sha256 in rows:
        entry = _core_entry(row, sha256 or "")
        entry["evidence_id"] = row.evidence_id
        chain.append(entry)
    return chain


def _core_only(chain: list[dict]) -> str:
    return json.dumps([{k: e[k] for k in _CORE_KEYS} for e in chain])


def chain_status(session: Session, engagement_id: str) -> dict:
    """Entries, root and verification computed from ONE read of the chain, so a report never pins a
    root covering N+1 entries next to a verification of N (a concurrent append between reads)."""
    chain = load_chain(session, engagement_id)
    core = _core_only(chain)
    return {
        "entries": chain,
        "root": kc.ledger_root(core),
        "verify": json.loads(kc.ledger_verify(core)),
    }


def verify_chain(session: Session, engagement_id: str) -> dict:
    return chain_status(session, engagement_id)["verify"]


def root(session: Session, engagement_id: str) -> str | None:
    return chain_status(session, engagement_id)["root"]
