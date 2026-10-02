"""Runs and the findings inbox (spec 005).

Starting a run needs the `operator` or `owner` engagement role; reading runs and findings is open to
any member. The scope lock is applied inside the run service, so an out-of-scope request returns a
`rejected` run rather than executing anything.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..deps import EngagementAccess, require_engagement_role
from ..models import Finding, Run
from ..runs import RunError, create_and_execute_run
from ..schemas import FindingOut, RunCreate, RunOut

router = APIRouter(prefix="/api/engagements", tags=["runs"])


@router.post("/{engagement_id}/runs", response_model=RunOut, status_code=201)
def create_run(
    body: RunCreate,
    access: EngagementAccess = Depends(require_engagement_role("owner", "operator")),
) -> Run:
    try:
        return create_and_execute_run(
            access, adapter_name=body.adapter, target_id=body.target_id, params=body.params
        )
    except RunError as e:
        raise HTTPException(e.status, e.detail) from e


@router.get("/{engagement_id}/runs", response_model=list[RunOut])
def list_runs(access: EngagementAccess = Depends(require_engagement_role())) -> list[Run]:
    rows = access.session.scalars(
        select(Run).where(Run.engagement_id == access.engagement.id).order_by(Run.created_at.desc())
    ).all()
    return list(rows)


@router.get("/{engagement_id}/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, access: EngagementAccess = Depends(require_engagement_role())) -> Run:
    run = access.session.get(Run, run_id)
    if run is None or run.engagement_id != access.engagement.id:
        raise HTTPException(404, "run not found in this engagement")
    return run


def _to_finding_out(f: Finding) -> FindingOut:
    xk = (f.body or {}).get("x-khandaq", {})
    return FindingOut(
        id=f.id,
        fingerprint=f.fingerprint,
        rule_id=f.rule_id or "",
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        status=f.status,
        phase=xk.get("phase"),
        mappings=xk.get("mappings", []),
        evidence=xk.get("evidence", []),
        also_found_by=xk.get("also_found_by", []),
    )


@router.get("/{engagement_id}/findings", response_model=list[FindingOut])
def findings_inbox(
    severity: str | None = None,
    access: EngagementAccess = Depends(require_engagement_role()),
) -> list[FindingOut]:
    stmt = select(Finding).where(
        Finding.engagement_id == access.engagement.id, Finding.canonical.is_(True)
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = access.session.scalars(stmt.order_by(Finding.created_at.desc())).all()
    return [_to_finding_out(f) for f in rows]
