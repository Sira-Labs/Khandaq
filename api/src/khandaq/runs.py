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
import logging
from collections.abc import Callable

import khandaq_core as kc
from sqlalchemy import and_, exists, not_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased
from sqlalchemy.orm.attributes import flag_modified

from . import audit, egress_forwarder, target_credentials
from .adapters import (
    AdapterManifest,
    all_manifests,
    build_run_request,
    get_manifest,
    get_runner,
)
from .adapters.docker import LeftoversError, remove_run_leftovers
from .campaign_diff import record_diff
from .credential_values import CredentialError, redact
from .deps import EngagementAccess
from .evidence_crypto import Keyring
from .evidence_store import EvidenceStore, retain, store_from_settings
from .ledger import lock_engagement, seal_evidence
from .mapping_overlay import current_overlay, provenance
from .models import AuditLog, Engagement, Finding, Run, Scope, Target, User
from .scope import evaluate
from .settings import get_settings

NOTIFY_CHANNEL = "khandaq_runs"
log = logging.getLogger("khandaq.runs")


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


def forwarder_pace(manifest: AdapterManifest, params: dict | None) -> object | None:
    """The declared ``rate_per_minute`` the run's egress forwarder will hold, or ``None`` when the
    run is not paced by it (spec 032 §4). Not yet validated: see ``usable_pace``."""
    if not manifest.forwarder_paced:
        return None
    return (params or {}).get("rate_per_minute")


def usable_pace(value: object) -> bool:
    """Whether the forwarder can pace at this rate: a finite number above 0 whose interval
    (``60 / rate``) is finite too. It is the forwarder's own rule, so the two agree."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return egress_forwarder.usable_pace(value)


def _capped(roe: dict | None) -> bool:
    return (roe or {}).get("max_requests_per_minute") is not None


def adapter_refusal(
    manifest: AdapterManifest, roe: dict | None, params: dict | None = None
) -> str | None:
    """Why this adapter cannot honour the engagement's rules of engagement, or ``None``
    (specs 027 and 032).

    The scope lock checks the requested ``rate_per_minute`` against the cap; this checks that the
    rate will actually be held: by the adapter itself (``paces_requests``) or by the run's egress
    forwarder (``forwarder_paced``). An adapter with neither is refused rather than trusted to
    stay under the cap.
    """
    pace = forwarder_pace(manifest, params)
    if pace is not None and not usable_pace(pace):
        # Also without a cap: a declared rate is kept, and this one cannot be.
        return (
            f"adapter '{manifest.name}' is paced by the run's forwarder, which needs a"
            f" rate_per_minute above 0, got {pace!r}: a rate of 0/min lets the run send nothing"
        )
    if not _capped(roe) or manifest.paces_requests or pace is not None:
        return None
    return (
        f"adapter '{manifest.name}' cannot hold the rules of engagement's request-rate limit;"
        " use an adapter that paces its requests, or an engagement without a rate limit"
    )


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
    return adapter_refusal(manifest, scope_row.roe if scope_row is not None else None, params)


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


def _start(
    session: Session,
    run: Run,
    target: Target,
    manifest: AdapterManifest,
    actor: User | None,
    **detail,
) -> None:
    """Mark the run running and audit it, including whether it will carry the target's credential
    (spec 028): ``injected``, ``none``, or ``not_accepted`` when the adapter takes none."""
    run.state = "running"
    run.started_at = _now()
    detail["credential"] = target_credentials.planned_use(session, target, manifest)
    pace = forwarder_pace(manifest, run.params)
    if pace is not None:
        detail["paced_per_minute"] = pace  # the rate the run's forwarder holds (spec 032)
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
    _start(session, run, target, manifest, access.user)
    session.commit()
    return execute_run(session, run.id, actor=access.user)


def claim_next_run(session: Session) -> str | None:
    """Worker: take the oldest queued run, re-check its scope, and mark it running or rejected.

    Returns the id of a run that is now ``running`` (committed), or ``None`` when the queue is
    empty or the claimed run was rejected. ``SKIP LOCKED`` makes concurrent workers take
    different runs.

    A forwarder-paced run of an engagement with a rate cap waits (stays ``queued``) while another
    such run of that engagement is running: each forwarder holds its own run's rate, so two side
    by side would exceed the engagement's cap together (spec 032 §6).
    """
    paced = [m.name for m in all_manifests() if m.forwarder_paced]
    held_back: list[str] = []  # runs another worker's paced run got in front of, this call
    while len(held_back) <= _MAX_HELD_BACK:
        claimed = _claim_one(session, paced, held_back)
        if claimed is not _HELD_BACK:
            return claimed
    return None


_HELD_BACK = "held back"
_MAX_HELD_BACK = 20


def _claim_one(session: Session, paced: list[str], held_back: list[str]) -> str | None:
    """One attempt of ``claim_next_run``. Returns ``_HELD_BACK`` (and notes the run) when the
    oldest claimable run has to wait after all, so the caller goes on to the next one instead of
    reporting an empty queue."""
    run = session.scalars(
        select(Run)
        .where(
            Run.state == "queued",
            Run.id.not_in(held_back),
            not_(_waits_for_paced_run(paced)),
        )
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
    if reason is not None or target is None or manifest is None:
        _reject(session, run, reason or "the target or the adapter is gone", None, at="claim")
        session.commit()
        return None
    scope_row = session.get(Scope, engagement.id)
    if manifest.forwarder_paced and scope_row is not None and _capped(scope_row.roe):
        # The query above skips a run that has to wait, but two workers can each pick one of two
        # queued runs at the same moment. Under the engagement lock only the first starts.
        lock_engagement(session, engagement.id)
        run_id = run.id
        if session.scalar(select(_other_paced_run_is_running(run.engagement_id, run_id, paced))):
            session.rollback()  # stays queued; taken once the running one has ended
            held_back.append(run_id)
            return _HELD_BACK
    _start(session, run, target, manifest, None, by="worker")
    session.commit()
    return run.id


def _other_paced_run_is_running(engagement_id, run_id, paced: list[str]):
    other = aliased(Run)
    return exists().where(
        other.engagement_id == engagement_id,
        other.id != run_id,
        other.state == "running",
        other.adapter.in_(paced),
    )


def _waits_for_paced_run(paced: list[str]):
    """SQL condition: this queued run is forwarder-paced, its engagement has a rate cap, and
    another forwarder-paced run of that engagement is running."""
    capped = exists().where(
        Scope.engagement_id == Run.engagement_id,
        Scope.roe["max_requests_per_minute"].astext.is_not(None),
    )
    return and_(
        Run.adapter.in_(paced),
        capped,
        _other_paced_run_is_running(Run.engagement_id, Run.id, paced),
    )


# How long after its claim a run may still start its tool. Everything from here on is bounded
# (the runner's own limits and the adapter timeout), and recovery's cutoff allows for this budget
# on top of them, so a run that starts is never taken for a lost one while it is running.
START_BUDGET = dt.timedelta(minutes=5)


class StartedTooLate(Exception):
    """The run did not reach the start of its tool within ``START_BUDGET`` of its claim."""


def _may_still_start(session: Session, run: Run) -> bool:
    """The fence in front of the tool (spec 032 §7). The steps before it (reloading the target,
    reading a credential) have no deadline of their own. If they took so long that recovery has
    already ended the run, nothing may start now: the engagement's next paced run may be running.
    ``False`` when the run is no longer ``running``; raises ``StartedTooLate`` when it still is
    but its budget is spent, so that it fails here instead of racing recovery."""
    session.refresh(run)
    if run.state != "running":
        log.error("run %s was ended while it was being prepared; it is not started", run.id)
        return False
    if run.started_at is not None and _now() - run.started_at > START_BUDGET:
        raise StartedTooLate(
            f"the run was not ready to start within {START_BUDGET.total_seconds():.0f}s "
            "of its claim"
        )
    return True


def execute_run(session: Session, run_id: str, *, actor: User | None = None, runner=None) -> Run:
    """Execute a ``running`` run and record the outcome; every failure ends in ``failed``, except
    a run whose containers could not be removed, which stays ``running`` (``_keep_running``)."""
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - the running row was committed before execution
        raise RuntimeError(f"run {run_id} does not exist")
    eng_id = run.engagement_id
    credential: str | None = None
    try:
        # Inside the boundary: reloading the target or the manifest can fail too.
        target = session.get(Target, run.target_id) if run.target_id else None
        manifest = get_manifest(run.adapter)
        if target is None or manifest is None:
            raise ValueError("the target or the adapter is gone")
        settings = get_settings()
        # The request never carries the credential (spec 028 §7): runners and adapters may log it.
        request = build_run_request(run_id, eng_id, target.type, target.spec, run.params or {})
        target_id = target.id
        # Only this run's own target, only if run.started recorded `injected`; an unusable
        # credential fails the run instead of running without one.
        credential = target_credentials.load_for_run(session, run, target, settings)
        active = runner or get_runner(manifest, settings)
        if not _may_still_start(session, run):
            return run  # recovery ended it meanwhile: its record stands, nothing is started
        if credential is None:
            artifacts = active.run(request)
        else:
            artifacts = active.run(request, credential=credential)
    except CredentialError as exc:
        return _fail(session, eng_id, run_id, f"target credential unusable: {exc.detail}", actor)
    except LeftoversError as exc:
        return _keep_running(session, eng_id, run_id, str(exc), actor)
    except StartedTooLate as exc:
        return _fail(session, eng_id, run_id, str(exc), actor)
    except Exception as exc:  # third-party tool execution: every failure is recorded, never lost
        # The runner redacts what the adapter returned; this covers any other text on the way out.
        return _fail(session, eng_id, run_id, redact(f"adapter failed: {exc}", credential), actor)

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
        error = redact(f"recording results failed: {exc}", credential)
        return _fail(session, eng_id, run_id, error, actor)

    session.refresh(run)
    return run


_LEFTOVERS_AT_RECOVERY = "the lost run's containers or network could not be removed"


def _audit_cleanup_failed_once(session: Session, run: Run, error: str) -> None:
    """Audit ``run.cleanup_failed`` for this run unless it already is: recovery comes back every
    few minutes, and the trail should say that the run is stuck, not how often it was looked at."""
    already = session.scalar(
        select(
            exists().where(
                AuditLog.engagement_id == run.engagement_id,
                AuditLog.action == "run.cleanup_failed",
                AuditLog.detail["run_id"].astext == run.id,
            )
        )
    )
    if not already:
        audit.record(
            session,
            action="run.cleanup_failed",
            engagement_id=run.engagement_id,
            detail={"run_id": run.id, "error": error},
        )


def _leftovers_removed(run: Run) -> bool:
    """Whether nothing of a lost container run is left on the Docker host."""
    manifest = get_manifest(run.adapter)
    if manifest is not None and manifest.builtin:
        return True  # ran in-process, left nothing
    # Whatever this deployment is configured to start now: the run was started by a worker that
    # could, and removal needs only the names derived from the run id.
    return remove_run_leftovers(run.id)


def recover_stale_runs(
    session: Session,
    *,
    older_than: dt.timedelta,
    leftovers_removed: Callable[[Run], bool] = _leftovers_removed,
) -> int:
    """Worker start: fail runs left ``running`` longer than any run can take (a lost worker).

    The lost worker never cleaned up, so the run's containers are removed first (spec 032): its
    forwarder could otherwise keep relaying beside the next paced run of the engagement. A run
    whose leftovers cannot be removed stays ``running``, which keeps holding that next run back,
    is audited once as ``run.cleanup_failed`` and is tried again at the next recovery.
    """
    cutoff = _now() - older_than
    stale = session.scalars(
        select(Run)
        .where(Run.state == "running", Run.started_at < cutoff)
        .with_for_update(skip_locked=True)
    ).all()
    failed = 0
    for run in stale:
        if not leftovers_removed(run):
            log.error("run %s was lost and its containers could not be removed", run.id)
            _audit_cleanup_failed_once(session, run, _LEFTOVERS_AT_RECOVERY)
            continue
        failed += 1
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
    return failed


_ERROR_CHARS, _ERROR_HEAD = 500, 140


def _brief(error: str) -> str:
    """An error cut to the recorded length, keeping its start and its end. A tool's last lines say
    why it stopped (a 401 from the target, for instance); its first lines only say that it began."""
    if len(error) <= _ERROR_CHARS:
        return error
    gap = " … "
    return error[:_ERROR_HEAD] + gap + error[-(_ERROR_CHARS - _ERROR_HEAD - len(gap)) :]


def _fail(session: Session, engagement_id: str, run_id: str, error: str, actor: User | None) -> Run:
    """Record a failed run in a fresh transaction (the current one may be unusable)."""
    session.rollback()
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - the running row was committed before execution
        raise RuntimeError(f"run {run_id} vanished before its failure could be recorded")
    run.state = "failed"
    run.ended_at = _now()
    run.reject_reason = brief = _brief(error)
    audit.record(
        session,
        action="run.failed",
        actor=actor,
        engagement_id=engagement_id,
        detail={"run_id": run_id, "error": brief},
    )
    session.commit()
    session.refresh(run)
    return run


def _keep_running(
    session: Session, engagement_id: str, run_id: str, error: str, actor: User | None
) -> Run:
    """The run is over but its containers could not be removed (spec 032): its forwarder may
    still be relaying, so the run stays ``running``, which keeps holding back the engagement's
    next paced run, and whatever it returned is dropped. Recovery removes the leftovers and fails
    the run once it is past the timeout. Audited, in a fresh transaction."""
    session.rollback()
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - the running row was committed before execution
        raise RuntimeError(f"run {run_id} vanished before its state could be recorded")
    log.error("run %s: %s; it stays running until they are removed", run_id, error)
    audit.record(
        session,
        action="run.cleanup_failed",
        actor=actor,
        engagement_id=engagement_id,
        detail={"run_id": run_id, "error": error},
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
