"""Engagement lifecycle, the scope lock pre-flight, and the audit log (spec 002).

Every privileged action is audited; the scope lock (khandaq.scope) is the control that keeps runs
inside the authorised boundary. Auth/roles come from khandaq.deps (a dev stub until spec 008).
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, scope
from ..deps import (
    EngagementAccess,
    current_user,
    get_session,
    require_engagement_role,
)
from ..models import AuditLog, Engagement, EngagementMember, Scope, Target, User
from ..schemas import (
    ActivateIn,
    AuditOut,
    EngagementCreate,
    EngagementOut,
    MemberOut,
    ScopeCheckIn,
    ScopeCheckOut,
    ScopeIn,
    ScopeOut,
    TargetCreate,
    TargetOut,
)

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(
    body: EngagementCreate,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> Engagement:
    if user.org_role == "read_only":
        raise HTTPException(403, "read-only users cannot create engagements")
    eng = Engagement(name=body.name, client=body.client, owner_user_id=user.id, state="draft")
    session.add(eng)
    session.flush()
    session.add(EngagementMember(engagement_id=eng.id, user_id=user.id, role="owner"))
    audit.record(
        session,
        action="engagement.created",
        actor=user,
        engagement_id=eng.id,
        detail={"name": eng.name},
    )
    session.commit()
    session.refresh(eng)
    return eng


@router.get("", response_model=list[EngagementOut])
def list_engagements(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[Engagement]:
    """Engagements the caller can see: all for an org admin, else those they are a member of."""
    if user.org_role == "admin":
        rows = session.scalars(select(Engagement).order_by(Engagement.created_at.desc())).all()
    else:
        rows = session.scalars(
            select(Engagement)
            .join(EngagementMember, EngagementMember.engagement_id == Engagement.id)
            .where(EngagementMember.user_id == user.id)
            .order_by(Engagement.created_at.desc())
        ).all()
    return list(rows)


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(access: EngagementAccess = Depends(require_engagement_role())) -> Engagement:
    return access.engagement


@router.get("/{engagement_id}/targets", response_model=list[TargetOut])
def list_targets(access: EngagementAccess = Depends(require_engagement_role())) -> list[Target]:
    rows = access.session.scalars(
        select(Target).where(Target.engagement_id == access.engagement.id)
    ).all()
    return list(rows)


@router.get("/{engagement_id}/scope", response_model=ScopeOut | None)
def get_scope(access: EngagementAccess = Depends(require_engagement_role())) -> Scope | None:
    return access.session.get(Scope, access.engagement.id)


@router.get("/{engagement_id}/members", response_model=list[MemberOut])
def list_members(access: EngagementAccess = Depends(require_engagement_role())) -> list[MemberOut]:
    rows = access.session.scalars(
        select(EngagementMember).where(EngagementMember.engagement_id == access.engagement.id)
    ).all()
    out = []
    for m in rows:
        user = access.session.get(User, m.user_id)
        out.append(MemberOut(user_id=m.user_id, role=m.role, email=user.email if user else None))
    return out


@router.post("/{engagement_id}/targets", response_model=TargetOut, status_code=201)
def add_target(
    body: TargetCreate,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> Target:
    if access.engagement.state != "draft":
        raise HTTPException(409, "targets can only be added while the engagement is in draft")
    target = Target(
        engagement_id=access.engagement.id,
        type=body.type,
        spec=body.spec,
        credential_ref=body.credential_ref,
    )
    access.session.add(target)
    audit.record(
        access.session,
        action="target.added",
        actor=access.user,
        engagement_id=access.engagement.id,
        detail={"type": body.type},
    )
    access.session.commit()
    access.session.refresh(target)
    return target


@router.put("/{engagement_id}/scope", response_model=ScopeOut)
def set_scope(
    body: ScopeIn,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> Scope:
    session, eng = access.session, access.engagement
    existing = session.get(Scope, eng.id)
    if eng.state == "closed":
        raise HTTPException(409, "cannot change scope on a closed engagement")

    if existing is None:
        existing = Scope(engagement_id=eng.id, allow=body.allow, deny=body.deny, roe=body.roe)
        session.add(existing)
        audit.record(
            session,
            action="scope.set",
            actor=access.user,
            engagement_id=eng.id,
            detail={"version": existing.version},
        )
    else:
        before = {
            "allow": existing.allow,
            "deny": existing.deny,
            "roe": existing.roe,
            "version": existing.version,
        }
        existing.allow, existing.deny, existing.roe = body.allow, body.deny, body.roe
        if eng.state == "active":
            # Changing a locked scope is owner-only and bumps the version, with before/after.
            existing.version += 1
            audit.record(
                session,
                action="scope.changed",
                actor=access.user,
                engagement_id=eng.id,
                detail={"before": before, "after_version": existing.version},
            )
        else:
            audit.record(
                session,
                action="scope.set",
                actor=access.user,
                engagement_id=eng.id,
                detail={"version": existing.version},
            )
    session.commit()
    session.refresh(existing)
    return existing


@router.post("/{engagement_id}/activate", response_model=EngagementOut)
def activate(
    body: ActivateIn,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> Engagement:
    session, eng = access.session, access.engagement
    if eng.state != "draft":
        raise HTTPException(409, f"cannot activate an engagement in state '{eng.state}'")
    scope_row = session.get(Scope, eng.id)
    target_count = session.scalar(select(Target).where(Target.engagement_id == eng.id).limit(1))
    problems = []
    if scope_row is None:
        problems.append("a scope must be set")
    if target_count is None:
        problems.append("at least one target is required")
    if not body.authorisation_ref.strip():
        problems.append("an authorisation reference is required")
    if problems:
        raise HTTPException(422, "cannot activate: " + "; ".join(problems))
    assert scope_row is not None  # guaranteed by the precondition check above

    eng.state = "active"
    eng.activated_at = _now()
    eng.authorisation_ref = body.authorisation_ref
    scope_row.locked = True
    audit.record(
        session,
        action="engagement.activated",
        actor=access.user,
        engagement_id=eng.id,
        detail={"authorisation_ref": body.authorisation_ref},
    )
    session.commit()
    session.refresh(eng)
    return eng


@router.post("/{engagement_id}/close", response_model=EngagementOut)
def close(access: EngagementAccess = Depends(require_engagement_role("owner"))) -> Engagement:
    session, eng = access.session, access.engagement
    if eng.state == "closed":
        raise HTTPException(409, "engagement is already closed")
    eng.state = "closed"
    eng.closed_at = _now()
    audit.record(session, action="engagement.closed", actor=access.user, engagement_id=eng.id)
    session.commit()
    session.refresh(eng)
    return eng


@router.post("/{engagement_id}/scope-check", response_model=ScopeCheckOut)
def scope_check(
    body: ScopeCheckIn,
    access: EngagementAccess = Depends(require_engagement_role()),
) -> ScopeCheckOut:
    session, eng = access.session, access.engagement
    target = session.get(Target, body.target_id)
    if target is None or target.engagement_id != eng.id:
        raise HTTPException(404, "target not found in this engagement")
    scope_row = session.get(Scope, eng.id)
    if scope_row is None:
        return ScopeCheckOut(allowed=False, reason="no scope defined for this engagement")
    decision = scope.evaluate(
        allow=scope_row.allow,
        deny=scope_row.deny,
        roe=scope_row.roe,
        target_type=target.type,
        target_spec=target.spec,
        params=body.params,
        now=_now(),
    )
    return ScopeCheckOut(allowed=decision.allowed, reason=decision.reason)


@router.get("/{engagement_id}/audit", response_model=list[AuditOut])
def get_audit(
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> list[AuditLog]:
    rows = access.session.scalars(
        select(AuditLog)
        .where(AuditLog.engagement_id == access.engagement.id)
        .order_by(AuditLog.at.asc())
    ).all()
    return list(rows)
