"""Run creation and execution (spec 005).

Creating a run applies the **same scope lock** as spec 002 on the run path: an out-of-scope call is
recorded as a `rejected` run and audited, and nothing is launched. An authorised run executes its
adapter, seals the evidence into the ledger (spec 004), normalises and deduplicates the findings
through the Rust core (spec 003), persists the canonical findings, and is audited throughout.

For R1 the built-in echo adapter runs in-process and synchronously; real tool adapters (Docker) and
asynchronous execution on the worker queue are a follow-up (ADR-0008).
"""

from __future__ import annotations

import datetime as dt
import json

import khandaq_core as kc
from sqlalchemy.orm import Session

from . import audit
from .adapters import build_run_request, get_manifest, get_runner
from .deps import EngagementAccess
from .ledger import seal_evidence
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


def create_and_execute_run(
    access: EngagementAccess, *, adapter_name: str, target_id: str, params: dict
) -> Run:
    session: Session = access.session
    eng = access.engagement

    manifest = get_manifest(adapter_name)
    if manifest is None:
        raise RunError(422, f"unknown adapter '{adapter_name}'")
    target = session.get(Target, target_id)
    if target is None or target.engagement_id != eng.id:
        raise RunError(404, "target not found in this engagement")

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

    # --- Execute (authorised) ---
    run.state = "running"
    run.started_at = _now()
    audit.record(
        session,
        action="run.started",
        actor=access.user,
        engagement_id=eng.id,
        detail={"run_id": run.id, "adapter": adapter_name},
    )
    session.flush()

    try:
        request = build_run_request(run.id, eng.id, target.type, target.spec, params)
        runner = get_runner(manifest, get_settings())
        artifacts = runner.run(request)

        # Seal each evidence artefact; map the adapter's local ids to persisted evidence ids.
        local_to_id: dict[str, str] = {}
        for ev in artifacts["evidence"]:
            evidence, _ = seal_evidence(
                session,
                engagement_id=eng.id,
                run_id=run.id,
                kind=ev["kind"],
                object_key=ev["object_key"],
                sha256=ev["sha256"],
                bytes_=ev.get("bytes", 0),
                redacted=ev.get("redacted", False),
            )
            local_to_id[ev["local_id"]] = evidence.id

        # Attach evidence ids, validate, then normalise + dedup via the core.
        raw = []
        for f in artifacts["findings"]:
            f["engagement_id"] = eng.id
            f["run_id"] = run.id
            f["x-khandaq"]["evidence"] = [local_to_id[k] for k in f.pop("_evidence_local", [])]
            kc.validate_finding(json.dumps(f))
            raw.append(f)
        result = json.loads(kc.dedup(json.dumps(raw)))

        for cf in result["canonical"]:
            xk = cf.get("x-khandaq", {})
            session.add(
                Finding(
                    engagement_id=eng.id,
                    run_id=run.id,
                    fingerprint=cf["fingerprint"],
                    canonical=True,
                    rule_id=cf["rule_id"],
                    title=cf.get("title"),
                    severity=cf["severity"],
                    confidence=cf.get("confidence", "firm"),
                    body=cf,
                    status=xk.get("status", "open"),
                )
            )

        run.state = "succeeded"
        run.ended_at = _now()
        audit.record(
            session,
            action="run.succeeded",
            actor=access.user,
            engagement_id=eng.id,
            detail={
                "run_id": run.id,
                "findings": len(result["canonical"]),
                "duplicates": result["duplicates"],
            },
        )
    except Exception as exc:  # execution failure — recorded, never silent
        run.state = "failed"
        run.reject_reason = f"execution failed: {exc}"[:500]
        audit.record(
            session,
            action="run.failed",
            actor=access.user,
            engagement_id=eng.id,
            detail={"run_id": run.id, "error": str(exc)[:500]},
        )

    session.commit()
    session.refresh(run)
    return run
