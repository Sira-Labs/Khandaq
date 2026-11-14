"""Target credentials (spec 028): set, replace and clear one write-only secret per target.

Owner only. There is no route that returns a stored value, and no response, error or audit entry
here contains one: the request body is read untyped so that a validation error cannot echo it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response

from .. import target_credentials
from ..credential_values import CredentialError
from ..deps import EngagementAccess, require_engagement_role
from ..models import Target
from ..schemas import CredentialOut
from ..settings import get_settings

router = APIRouter(prefix="/api/engagements", tags=["credentials"])


def _target(access: EngagementAccess, target_id: str) -> Target:
    target = access.session.get(Target, target_id)
    if target is None or target.engagement_id != access.engagement.id:
        raise HTTPException(404, "target not found in this engagement")
    return target


@router.put("/{engagement_id}/targets/{target_id}/credential", response_model=CredentialOut)
def set_credential(
    target_id: str,
    body: Any = Body(...),
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> CredentialOut:
    target = _target(access, target_id)
    # The state is read under the lock that closing takes, so a credential cannot slip in behind
    # a concurrent close.
    if target_credentials.lock_for_change(access.session, access.engagement).state == "closed":
        raise HTTPException(409, "a closed engagement holds no credentials")
    value = body.get("value") if isinstance(body, dict) else None
    try:
        row = target_credentials.set_credential(
            access.session, target, value, actor=access.user, settings=get_settings()
        )
    except CredentialError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    access.session.commit()  # the credential and its audit entry, or neither
    access.session.refresh(row)
    return CredentialOut(has_credential=True, version=row.version, updated_at=row.updated_at)


@router.delete("/{engagement_id}/targets/{target_id}/credential", status_code=204)
def clear_credential(
    target_id: str,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> Response:
    target = _target(access, target_id)
    target_credentials.lock_for_change(access.session, access.engagement)
    row = target_credentials.get(access.session, target.id)
    if row is None:
        raise HTTPException(404, "this target has no credential")
    target_credentials.clear_credential(
        access.session, row, actor=access.user, reason="removed by the owner"
    )
    access.session.commit()
    return Response(status_code=204)
