"""Run creation and execution (spec 005).

Creating a run applies the **same scope lock** as spec 002 on the run path: an out-of-scope call is
recorded as a `rejected` run and audited, and nothing is launched. An authorised run executes its
adapter, seals the evidence into the ledger (spec 004), normalises and deduplicates the findings
through the Rust core (spec 003), persists the canonical findings, and is audited throughout.

For R1 the built-in echo adapter runs in-process and synchronously; real tool adapters (Docker) and
asynchronous execution on the worker queue are a follow-up (ADR-0008).

Record durability (code review, 2026-10-02): the run row and ``run.started`` are **committed
before** the adapter touches the target, and any later failure is recorded in a fresh transaction.
Before, both were only flushed, so a database error while saving results rolled back the whole
record of a run that had already reached the target. Results are persisted under a per-engagement
lock, which serialises ledger appends and cross-run deduplication between concurrent runs.
"""

from __future__ import annotations

import datetime as dt
import json

import khandaq_core as kc
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from . import audit
from .adapters import build_run_request, get_manifest, get_runner
from .deps import EngagementAccess
from .ledger import lock_engagement, seal_evidence
from .models import Finding, Run, Scope, Target
from .scope import evaluate
from .settings import get_settings


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class RunError(Exception):
    """Raised for client errors during run creation (mapped to HTTP by the router)."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _refuse(access: EngagementAccess, status: int, detail: str, **context: str) -> RunError:
    """Audit a refusal that happens before a run row exists (unknown adapter, foreign target), so
    probing for another engagement's target ids leaves a trace."""
    audit.record(
        access.session,
        action="run.refused",
        actor=access.user,
        engagement_id=access.engagement.id,
        detail={"reason": detail, **context},
    )
    access.session.commit()
    return RunError(status, detail)


def create_and_execute_run(
    access: EngagementAccess, *, adapter_name: str, target_id: str, params: dict
) -> Run:
    session: Session = access.session
    eng = access.engagement

    manifest = get_manifest(adapter_name)
    if manifest is None:
        raise _refuse(access, 422, f"unknown adapter '{adapter_name}'", adapter=adapter_name)
    target = session.get(Target, target_id)
    if target is None or target.engagement_id != eng.id:
        raise _refuse(access, 404, "target not found in this engagement", target_id=target_id)

    run = Run(
        engagement_id=eng.id,
        adapter=adapter_name,
        adapter_version=manifest.version,
        target_id=target_id,
        params=params,
        state="queued",
    )
    session.add(run)
    session.flush()

    # --- Scope lock on the run path (default deny) ---
    scope_row = session.get(Scope, eng.id)
    reason: str | None = None
    if eng.state != "active":
        reason = f"engagement is '{eng.state}', not active"
    elif scope_row is None:
        reason = "no scope defined for this engagement"
    else:
        decision = evaluate(
            allow=scope_row.allow,
            deny=scope_row.deny,
            roe=scope_row.roe,
            target_type=target.type,
            target_spec=target.spec,
            params=params,
            now=_now(),
        )
        reason = None if decision.allowed else decision.reason

    if reason is not None:
        run.state = "rejected"
        run.reject_reason = reason
        audit.record(
            session,
            action="run.rejected",
            actor=access.user,
            engagement_id=eng.id,
            detail={"run_id": run.id, "adapter": adapter_name, "reason": reason},
        )
        session.commit()
        session.refresh(run)
        return run

    # --- Authorised: make the record durable BEFORE anything reaches the target ---
    run.state = "running"
    run.started_at = _now()
    audit.record(
        session,
        action="run.started",
        actor=access.user,
        engagement_id=eng.id,
        detail={"run_id": run.id, "adapter": adapter_name},
    )
    session.commit()
    run_id = run.id

    request = build_run_request(run_id, eng.id, target.type, target.spec, params)
    try:
        artifacts = get_runner(manifest, get_settings()).run(request)
    except Exception as exc:  # third-party tool execution: every failure is recorded, never lost
        return _fail(access, run_id, f"adapter failed: {exc}")

    try:
        result = _persist_results(session, eng.id, run_id, target.id, artifacts)
        run.state = "succeeded"
        run.ended_at = _now()
        audit.record(
            session,
            action="run.succeeded",
            actor=access.user,
            engagement_id=eng.id,
            detail={"run_id": run_id, **result},
        )
        session.commit()  # also releases the engagement lock
    except (SQLAlchemyError, ValueError, KeyError, TypeError) as exc:
        # Bad adapter output (schema/validation) or a database error while saving results.
        return _fail(access, run_id, f"recording results failed: {exc}")

    session.refresh(run)
    return run


def _fail(access: EngagementAccess, run_id: str, error: str) -> Run:
    """Record a failed run in a fresh transaction (the current one may be unusable)."""
    session = access.session
    session.rollback()
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - the running row was committed before execution
        raise RuntimeError(f"run {run_id} vanished before its failure could be recorded")
    run.state = "failed"
    run.ended_at = _now()
    run.reject_reason = error[:500]
    audit.record(
        session,
        action="run.failed",
        actor=access.user,
        engagement_id=access.engagement.id,
        detail={"run_id": run_id, "error": error[:500]},
    )
    session.commit()
    session.refresh(run)
    return run


def _persist_results(
    session: Session, engagement_id: str, run_id: str, target_id: str, artifacts: dict
) -> dict:
    """Seal evidence and store findings under the engagement lock; the caller commits."""
    lock_engagement(session, engagement_id)

    # Seal each evidence artefact; map the adapter's local ids to persisted evidence ids.
    local_to_id: dict[str, str] = {}
    for ev in artifacts["evidence"]:
        evidence, _ = seal_evidence(
            session,
            engagement_id=engagement_id,
            run_id=run_id,
            kind=ev["kind"],
            object_key=ev["object_key"],
            sha256=ev["sha256"],
            bytes_=ev.get("bytes", 0),
            redacted=ev.get("redacted", False),
        )
        local_to_id[ev["local_id"]] = evidence.id

    # Identity fields are set by the server, never trusted from the adapter: the fingerprint uses
    # target_ref, so it names the real target row rather than an adapter-chosen label.
    raw = []
    for f in artifacts["findings"]:
        f["engagement_id"] = engagement_id
        f["run_id"] = run_id
        f["target_ref"] = target_id
        f["x-khandaq"]["evidence"] = [local_to_id[k] for k in f.pop("_evidence_local", [])]
        kc.validate_finding(json.dumps(f))
        raw.append(f)
    result = json.loads(kc.dedup(json.dumps(raw)))

    new, linked = 0, 0
    for cf in result["canonical"]:
        existing = session.scalars(
            select(Finding).where(
                Finding.engagement_id == engagement_id,
                Finding.fingerprint == cf["fingerprint"],
                Finding.canonical.is_(True),
            )
        ).first()
        session.add(
            Finding(
                engagement_id=engagement_id,
                run_id=run_id,
                fingerprint=cf["fingerprint"],
                canonical=existing is None,
                dedup_of=existing.id if existing is not None else None,
                rule_id=cf["rule_id"],
                title=cf.get("title"),
                severity=cf["severity"],
                confidence=cf.get("confidence", "firm"),
                body=cf,
                status="open",  # triage is the analyst's call, never the tool's
            )
        )
        if existing is None:
            new += 1
        else:
            _merge_into(existing, cf)
            linked += 1
    return {"findings": new, "linked_to_existing": linked, "duplicates": result["duplicates"]}


def _merge_into(canonical: Finding, duplicate: dict) -> None:
    """Fold a later run's duplicate into the engagement's canonical finding (ADR-0003): union the
    tools that found it and the evidence that backs it."""
    body = canonical.body
    xk = body.setdefault("x-khandaq", {})
    dup_xk = duplicate.get("x-khandaq", {})
    tools = set(xk.get("also_found_by", [])) | set(dup_xk.get("also_found_by", []))
    dup_tool = (duplicate.get("source") or {}).get("tool")
    own_tool = (body.get("source") or {}).get("tool")
    if dup_tool and dup_tool != own_tool:
        tools.add(dup_tool)
    xk["also_found_by"] = sorted(tools)
    evidence = list(xk.get("evidence", []))
    evidence += [e for e in dup_xk.get("evidence", []) if e not in evidence]
    xk["evidence"] = evidence
    flag_modified(canonical, "body")
