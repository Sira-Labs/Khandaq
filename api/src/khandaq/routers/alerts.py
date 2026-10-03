"""Alert outbox read endpoint (spec 017). Owners, operators and analysts see an engagement's alerts;
the payload carries rule ids and counts only."""

from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from ..deps import EngagementAccess, require_engagement_role
from ..models import AlertOutbox

router = APIRouter(prefix="/api/engagements", tags=["alerts"])


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    campaign_id: str
    diff_id: str
    payload: dict[str, Any]
    state: str
    attempts: int
    next_attempt_at: dt.datetime
    last_error: str | None
    created_at: dt.datetime
    sent_at: dt.datetime | None


@router.get("/{engagement_id}/alerts", response_model=list[AlertOut])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    access: EngagementAccess = Depends(require_engagement_role("owner", "operator", "analyst")),
) -> list[AlertOutbox]:
    return list(
        access.session.scalars(
            select(AlertOutbox)
            .where(AlertOutbox.engagement_id == access.engagement.id)
            .order_by(AlertOutbox.created_at.desc(), AlertOutbox.id.desc())
            .limit(limit)
        )
    )
