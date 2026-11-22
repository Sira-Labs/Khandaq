"""Engagement lifecycle, the scope lock pre-flight, and the audit log (spec 002).

Every privileged action is audited; the scope lock (khandaq.scope) is the control that keeps runs
inside the authorised boundary. Auth/roles come from khandaq.deps (a dev stub until spec 008).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import artefacts, audit, campaigns, scope, target_credentials
from ..adapters import get_manifest
from ..deps import (
    EngagementAccess,
    current_user,
    get_session,
    require_engagement_role,
)
from ..models import (
    AuditLog,
    Engagement,
    EngagementMember,
    Scope,
    Target,
    TargetArtefact,
    TargetCredential,
    User,
)
from ..runs import adapter_refusal
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


def target_out(
    target: Target,
    credential: TargetCredential | None = None,
    artefact: TargetArtefact | None = None,
) -> TargetOut:
    """A target as the API shows it: whether a credential or content is stored, never either."""
    return TargetOut(
        id=target.id,
        engagement_id=target.engagement_id,
        type=target.type,
        spec=target.spec,
        has_credential=credential is not None,
        credential_updated_at=credential.updated_at if credential is not None else None,
        has_artefact=artefact is not None,
        artefact_bytes=artefact.bytes if artefact is not None else None,
    )


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
def list_targets(access: EngagementAccess = Depends(require_engagement_role())) -> list[TargetOut]:
    rows = access.session.scalars(
        select(Target).where(Target.engagement_id == access.engagement.id)
    ).all()
    credentials = target_credentials.by_target(access.session, access.engagement.id)
    stored = artefacts.by_target(access.session, access.engagement.id)
    return [target_out(t, credentials.get(t.id), stored.get(t.id)) for t in rows]


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
    payload: Any = Body(...),
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> TargetOut:
    # The body is validated here, not by the framework, whose 422 repeats the submitted body:
    # someone may have pasted a secret into the old credential_ref field (spec 028).
    if isinstance(payload, dict) and "credential_ref" in payload:
        # Refused rather than kept or silently dropped.
        raise HTTPException(
            422,
            "credential_ref is no longer accepted; send the key to the target's credential route",
        )
    try:
        body = TargetCreate.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors(include_input=False, include_url=False)) from None
    if access.engagement.state != "draft":
        raise HTTPException(409, "targets can only be added while the engagement is in draft")
    problem = scope.validate_target(body.type, body.spec)
    if problem is not None:  # e.g. a spec naming two hosts the lock could not check consistently
        raise HTTPException(422, f"target cannot be scope-checked: {problem}")
    target = Target(
        engagement_id=access.engagement.id,
        type=body.type,
        spec=body.spec,
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
    return target_out(target)


@router.put("/{engagement_id}/scope", response_model=ScopeOut)
def set_scope(
    body: ScopeIn,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> Scope:
    session, eng = access.session, access.engagement
    existing = session.get(Scope, eng.id)
    if eng.state == "closed":
        raise HTTPException(409, "cannot change scope on a closed engagement")
    errors = scope.validate_scope(body.allow, body.deny, body.roe)
    if errors:
        raise HTTPException(422, {"scope_errors": errors})
    after = {"allow": body.allow, "deny": body.deny, "roe": body.roe}

    if existing is None:
        existing = Scope(engagement_id=eng.id, allow=body.allow, deny=body.deny, roe=body.roe)
        session.add(existing)
        audit.record(
            session,
            action="scope.set",
            actor=access.user,
            engagement_id=eng.id,
            detail={"version": 1, "after": after},
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
                detail={"before": before, "after": after, "after_version": existing.version},
            )
        else:
            audit.record(
                session,
                action="scope.set",
                actor=access.user,
                engagement_id=eng.id,
                detail={"version": existing.version, "before": before, "after": after},
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
    # Under the lock credential changes take: none can commit after the deletion below (spec 028).
    target_credentials.lock_for_change(session, eng)
    if eng.state == "closed":
        raise HTTPException(409, "engagement is already closed")
    eng.state = "closed"
    eng.closed_at = _now()
    audit.record(session, action="engagement.closed", actor=access.user, engagement_id=eng.id)
    # Its campaigns stop with it, in the same transaction (spec 016 §5).
    campaigns.disable_for_closed_engagement(session, eng.id, actor=access.user)
    # So do its target credentials: a closed engagement holds no live secret (spec 028 §5).
    target_credentials.clear_for_closed_engagement(session, eng.id, actor=access.user)
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
    if decision.allowed and body.adapter is not None:
        manifest = get_manifest(body.adapter)
        if manifest is None:
            raise HTTPException(422, f"unknown adapter '{body.adapter}'")
        reason = adapter_refusal(manifest, scope_row.roe)
        if reason is not None:
            return ScopeCheckOut(allowed=False, reason=reason)
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
