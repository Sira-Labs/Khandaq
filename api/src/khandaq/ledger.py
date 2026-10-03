"""Evidence ledger service (spec 004).

Seals evidence into the append-only, hash-chained ledger and verifies the chain, delegating the
hashing to the Rust core via the `khandaq_core` wheel (ADR-0007/0011). The core LedgerEntry model
is {seq, evidence_hash, prev_hash, entry_hash, format}; in the database the entry references an
Evidence row, and `evidence_hash` is derived from that row by the entry's format (ADR-0014):

- format 1 (entries sealed before migration 0005): the artefact's sha256 alone;
- format 2: the core's ``evidence_record_hash`` over the row's id, engagement, run, kind, object
  key, sha256, size and redaction flag — so relabelling or moving sealed evidence breaks the chain.
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


def _record(evidence: Evidence) -> dict:
    """The evidence fields a format-2 entry seals (the core refuses any other field)."""
    return {
        "id": evidence.id,
        "engagement_id": evidence.engagement_id,
        "run_id": evidence.run_id,
        "kind": evidence.kind,
        "object_key": evidence.object_key,
        "sha256": evidence.sha256,
        "bytes": evidence.bytes,
        "redacted": evidence.redacted,
    }


def _evidence_hash(evidence: Evidence | None, format_: int) -> str:
    """What the entry seals for this evidence row under its format. A missing row, an unknown
    format or a record the core refuses yields "" — a malformed hash, so verification reports the
    chain broken at that entry instead of the request failing."""
    if evidence is None:
        return ""
    if format_ == 1:
        return evidence.sha256
    if format_ == 2:
        try:
            return kc.evidence_record_hash(json.dumps(_record(evidence)))
        except ValueError:
            return ""
    return ""


def _core_entry(row: LedgerEntry, evidence: Evidence | None) -> dict:
    return {
        "seq": row.seq,
        "evidence_hash": _evidence_hash(evidence, row.format),
        "prev_hash": row.prev_hash,
        "entry_hash": row.entry_hash,
        "format": row.format,
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
        prev_json = json.dumps(_core_entry(last, session.get(Evidence, last.evidence_id)))
    # The core refuses a malformed sha256 or record (ValueError) before anything is chained.
    sealed = kc.evidence_record_hash(json.dumps(_record(evidence)))
    entry = json.loads(kc.ledger_append(prev_json, sealed))
    if entry["format"] != 2:  # this service derives evidence_hash for formats 1 and 2 only
        # ValueError, so the run path records the run as failed instead of leaving it running.
        raise ValueError(f"khandaq_core writes ledger format {entry['format']}, expected 2")

    row = LedgerEntry(
        engagement_id=engagement_id,
        seq=entry["seq"],
        evidence_id=evidence.id,
        entry_hash=entry["entry_hash"],
        prev_hash=entry["prev_hash"],
        format=entry["format"],
    )
    session.add(row)
    session.flush()
    return evidence, row


_CORE_KEYS = ("seq", "evidence_hash", "prev_hash", "entry_hash", "format")


def load_chain(session: Session, engagement_id: str) -> list[dict]:
    """Return the chain as core LedgerEntry dicts (ordered by seq), each with its evidence_id.

    One joined query (it used to issue one evidence lookup per entry)."""
    rows = session.execute(
        select(LedgerEntry, Evidence)
        .outerjoin(Evidence, Evidence.id == LedgerEntry.evidence_id)
        .where(LedgerEntry.engagement_id == engagement_id)
        .order_by(LedgerEntry.seq.asc())
    ).all()
    chain = []
    for row, evidence in rows:
        entry = _core_entry(row, evidence)
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
