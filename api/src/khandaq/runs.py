"""Run creation and execution (spec 005, spec 012, spec 014).

Creating a run applies the **same scope lock** as spec 002 on the run path: an out-of-scope call is
recorded as a `rejected` run and audited, and nothing is launched. An authorised run executes its
adapter, seals the evidence into the ledger (spec 004), normalises and deduplicates the findings
through the Rust core (spec 003), persists the canonical findings, and is audited throughout.

Two paths (spec 012, ADR-0015):

- **Builtin** adapters (the in-process ``echo``) run synchronously in the request.
- **Container** adapters are committed ``queued`` (``run.queued``) and announced with
  ``NOTIFY khandaq_runs``. The worker claims the oldest queued run with ``FOR UPDATE SKIP LOCKED``,
  **re-checks the scope lock at claim time** (the engagement may have been paused, the scope
  narrowed or the window closed since), and then executes it exactly like a builtin run.

Record durability (code review, 2026-10-02): the run row and ``run.started`` are **committed
before** the adapter touches the target, and any later failure is recorded in a fresh transaction.
Results are persisted under a per-engagement lock, which serialises ledger appends and cross-run
deduplication between concurrent runs. Evidence bytes are stored encrypted and write-once before
their hash is sealed (spec 014, ADR-0016).
"""

from __future__ import annotations

import datetime as dt
import json

import khandaq_core as kc
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from . import audit
from .adapters import AdapterManifest, build_run_request, get_manifest, get_runner
from .campaign_diff import record_diff
from .deps import EngagementAccess
from .evidence_crypto import Keyring
from .evidence_store import EvidenceStore, retain, store_from_settings
from .ledger import lock_engagement, seal_evidence
from .mapping_overlay import current_overlay, provenance
from .models import Engagement, Finding, Run, Scope, Target, User
from .scope import evaluate
from .settings import get_settings

NOTIFY_CHANNEL = "khandaq_runs"


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


def scope_refusal(
    session: Session, engagement: Engagement, target: Target | None, params: dict
) -> str | None:
    """Why the scope lock refuses this run now, or ``None`` if it may proceed (default deny)."""
    if target is None or target.engagement_id != engagement.id:
        return "the target no longer exists in this engagement"
    if engagement.state != "active":
        return f"engagement is '{engagement.state}', not active"
    scope_row = session.get(Scope, engagement.id)
    if scope_row is None:
        return "no scope defined for this engagement"
    decision = evaluate(
        allow=scope_row.allow,
        deny=scope_row.deny,
        roe=scope_row.roe,
        target_type=target.type,
        target_spec=target.spec,
        params=params,
        now=_now(),
    )
    return None if decision.allowed else decision.reason


def adapter_refusal(manifest: AdapterManifest, roe: dict | None) -> str | None:
    """Why this adapter cannot honour the engagement's rules of engagement, or ``None`` (spec 027).

    The scope lock checks the requested ``rate_per_minute`` against the cap; this checks that the
    adapter can actually hold a rate. One that cannot is refused rather than trusted to stay under.
    """
    if (roe or {}).get("max_requests_per_minute") is not None and not manifest.paces_requests:
        return (
            f"adapter '{manifest.name}' cannot hold the rules of engagement's request-rate limit;"
            " use an adapter that paces its requests, or an engagement without a rate limit"
        )
    return None


def run_refusal(
    session: Session,
    engagement: Engagement,
    target: Target | None,
    manifest: AdapterManifest,
    params: dict,
) -> str | None:
    """The scope lock, then the adapter's ability to honour the rules of engagement."""
    reason = scope_refusal(session, engagement, target, params)
    if reason is not None:
        return reason
    scope_row = session.get(Scope, engagement.id)
    return adapter_refusal(manifest, scope_row.roe if scope_row is not None else None)


def _reject(session: Session, run: Run, reason: str, actor: User | None, **detail) -> None:
    run.state = "rejected"
    run.reject_reason = reason
    audit.record(
        session,
        action="run.rejected",
        actor=actor,
        engagement_id=run.engagement_id,
        detail={"run_id": run.id, "adapter": run.adapter, "reason": reason, **detail},
    )


def _start(session: Session, run: Run, actor: User | None, **detail) -> None:
    run.state = "running"
    run.started_at = _now()
    audit.record(
        session,
        action="run.started",
        actor=actor,
        engagement_id=run.engagement_id,
        detail={"run_id": run.id, "adapter": run.adapter, **detail},
    )


def _new_run(
    session: Session,
    engagement: Engagement,
    target: Target,
    adapter_name: str,
    adapter_version: str | None,
    params: dict,
    campaign_id: str | None = None,
) -> Run:
    run = Run(
        engagement_id=engagement.id,
        adapter=adapter_name,
        adapter_version=adapter_version,
        target_id=target.id,
        params=params,
        state="queued",
        campaign_id=campaign_id,
    )
    session.add(run)
    session.flush()
    return run


def _queue(session: Session, run: Run, actor: User | None, **detail) -> None:
    audit.record(
        session,
        action="run.queued",
        actor=actor,
        engagement_id=run.engagement_id,
        detail={"run_id": run.id, "adapter": run.adapter, **detail},
    )
    session.execute(text(f"NOTIFY {NOTIFY_CHANNEL}"))  # delivered on commit


def queue_run(
    session: Session,
    engagement: Engagement,
    target: Target,
    adapter_name: str,
    params: dict,
    *,
    actor: User | None,
    campaign_id: str | None = None,
) -> Run:
    """Create a run for the worker: ``rejected`` by the scope lock (audited) or ``queued``
    (audited). Builtin adapters are queued too; the worker executes them. Caller commits.

    The campaign scheduler's entry point (spec 016): a scheduled run passes the same scope lock and
    leaves the same trail as one a person starts."""
    manifest = get_manifest(adapter_name)
    if manifest is None:
        raise ValueError(f"unknown adapter '{adapter_name}'")
    run = _new_run(session, engagement, target, adapter_name, manifest.version, params, campaign_id)
    context = {"campaign_id": campaign_id} if campaign_id else {}
    reason = run_refusal(session, engagement, target, manifest, params)
    if reason is not None:
        _reject(session, run, reason, actor, **context)
    else:
        _queue(session, run, actor, **context)
    return run


def create_run(access: EngagementAccess, *, adapter_name: str, target_id: str, params: dict) -> Run:
    """Create a run: rejected (scope), executed now (builtin), or queued for the worker."""
    session: Session = access.session
    eng = access.engagement

    manifest = get_manifest(adapter_name)
    if manifest is None:
        raise _refuse(access, 422, f"unknown adapter '{adapter_name}'", adapter=adapter_name)
    target = session.get(Target, target_id)
    if target is None or target.engagement_id != eng.id:
        raise _refuse(access, 404, "target not found in this engagement", target_id=target_id)

    run = _new_run(session, eng, target, adapter_name, manifest.version, params)
    reason = run_refusal(session, eng, target, manifest, params)
    if reason is not None:
        _reject(session, run, reason, access.user)
        session.commit()
        session.refresh(run)
        return run

    if not manifest.builtin:
        _queue(session, run, access.user)
        session.commit()
        session.refresh(run)
        return run

    # Builtin: make the record durable BEFORE anything reaches the target, then run it here.
    _start(session, run, access.user)
    session.commit()
    return execute_run(session, run.id, actor=access.user)


def claim_next_run(session: Session) -> str | None:
    """Worker: take the oldest queued run, re-check its scope, and mark it running or rejected.

    Returns the id of a run that is now ``running`` (committed), or ``None`` when the queue is
    empty or the claimed run was rejected. ``SKIP LOCKED`` makes concurrent workers take
    different runs.
    """
    run = session.scalars(
        select(Run)
        .where(Run.state == "queued")
        .order_by(Run.created_at, Run.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    ).first()
    if run is None:
        session.rollback()
        return None
    engagement = session.get(Engagement, run.engagement_id)
    target = session.get(Target, run.target_id) if run.target_id else None
    if engagement is None:  # pragma: no cover - engagements are never deleted
        raise RuntimeError(f"run {run.id} has no engagement")
    manifest = get_manifest(run.adapter)
    if manifest is None:
        reason: str | None = f"adapter '{run.adapter}' is no longer available"
    else:
        reason = run_refusal(session, engagement, target, manifest, run.params or {})
    if reason is not None:
        _reject(session, run, reason, None, at="claim")
        session.commit()
        return None
    _start(session, run, None, by="worker")
    session.commit()
    return run.id


def execute_run(session: Session, run_id: str, *, actor: User | None = None, runner=None) -> Run:
    """Execute a ``running`` run and record the outcome; every failure ends in ``failed``."""
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - the running row was committed before execution
        raise RuntimeError(f"run {run_id} does not exist")
    eng_id = run.engagement_id
    try:
        # Inside the boundary: reloading the target or the manifest can fail too.
        target = session.get(Target, run.target_id) if run.target_id else None
        manifest = get_manifest(run.adapter)
        if target is None or manifest is None:
            raise ValueError("the target or the adapter is gone")
        request = build_run_request(run_id, eng_id, target.type, target.spec, run.params or {})
        target_id = target.id
        artifacts = (runner or get_runner(manifest, get_settings())).run(request)
    except Exception as exc:  # third-party tool execution: every failure is recorded, never lost
        return _fail(session, eng_id, run_id, f"adapter failed: {exc}", actor)

    try:
        result = _persist_results(session, eng_id, run_id, target_id, artifacts)
        run.state = "succeeded"
        run.ended_at = _now()
        if run.campaign_id is not None:  # spec 016: the diff exists exactly when the run succeeded
            record_diff(session, run)
        audit.record(
            session,
            action="run.succeeded",
            actor=actor,
            engagement_id=eng_id,
            detail={"run_id": run_id, **result},
        )
        session.commit()  # also releases the engagement lock
    except (SQLAlchemyError, ValueError, LookupError, TypeError, OSError) as exc:
        # Bad adapter output (schema/validation), evidence storage (spec 014: no key, a conflicting
        # object, an object-store error), or a database error.
        return _fail(session, eng_id, run_id, f"recording results failed: {exc}", actor)

    session.refresh(run)
    return run


def recover_stale_runs(session: Session, *, older_than: dt.timedelta) -> int:
    """Worker start: fail runs left ``running`` longer than any run can take (a lost worker)."""
    cutoff = _now() - older_than
    stale = session.scalars(
        select(Run)
        .where(Run.state == "running", Run.started_at < cutoff)
        .with_for_update(skip_locked=True)
    ).all()
    for run in stale:
        run.state = "failed"
        run.ended_at = _now()
        run.reject_reason = "the worker lost the run (still running past the timeout)"
        audit.record(
            session,
            action="run.failed",
            engagement_id=run.engagement_id,
            detail={"run_id": run.id, "error": run.reject_reason},
        )
    session.commit()
    return len(stale)


def _fail(session: Session, engagement_id: str, run_id: str, error: str, actor: User | None) -> Run:
    """Record a failed run in a fresh transaction (the current one may be unusable)."""
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
        actor=actor,
        engagement_id=engagement_id,
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
    store: EvidenceStore | None = None
    keyring: Keyring | None = None
    for ev in artifacts["evidence"]:
        if "content" in ev:  # container runs return the bytes: store them encrypted, then seal
            if keyring is None or store is None:
                settings = get_settings()
                keyring = Keyring.from_settings(settings)  # no key → the run fails before sealing
                store = store_from_settings(settings)
            retain(store, keyring, ev["object_key"], ev["content"], ev["sha256"])
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
    overlay = current_overlay()
    mapped_with = provenance()
    for f in artifacts["findings"]:
        f["engagement_id"] = engagement_id
        f["run_id"] = run_id
        f["target_ref"] = target_id
        f["x-khandaq"]["evidence"] = [local_to_id[k] for k in f.pop("_evidence_local", [])]
        kc.validate_finding(json.dumps(f))
        # The tool's framework ids plus the core table's, or an explicit `unmapped` marker
        # (spec 020, ADR-0012). Mappings are not identity (ADR-0013): no fingerprint moves.
        f["x-khandaq"]["mappings"] = json.loads(
            kc.merge_mappings(json.dumps(f), overlay.text if overlay else None)
        )
        f["x-khandaq"]["mapping_table"] = mapped_with
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
