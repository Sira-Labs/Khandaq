"""Campaign endpoints (spec 016). Owners and operators create and change campaigns (they cause
runs against the target); any member reads them and their diffs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from .. import campaigns
from ..deps import EngagementAccess, require_engagement_role
from ..models import Campaign, CampaignDiff, Run
from ..schemas import CampaignCreate, CampaignOut, CampaignUpdate, DiffOut, RunOut

router = APIRouter(prefix="/api/engagements", tags=["campaigns"])

_WRITERS = ("owner", "operator")


def _campaign(access: EngagementAccess, campaign_id: str) -> Campaign:
    campaign = access.session.get(Campaign, campaign_id)
    if campaign is None or campaign.engagement_id != access.engagement.id:
        raise HTTPException(404, "campaign not found")
    return campaign


@router.post("/{engagement_id}/campaigns", response_model=CampaignOut, status_code=201)
def create(
    body: CampaignCreate, access: EngagementAccess = Depends(require_engagement_role(*_WRITERS))
) -> Campaign:
    try:
        return campaigns.create_campaign(access, body)
    except campaigns.CampaignError as exc:
        raise HTTPException(exc.status, exc.detail) from None


@router.get("/{engagement_id}/campaigns", response_model=list[CampaignOut])
def list_campaigns(access: EngagementAccess = Depends(require_engagement_role())) -> list[Campaign]:
    return list(
        access.session.scalars(
            select(Campaign)
            .where(Campaign.engagement_id == access.engagement.id)
            .order_by(Campaign.created_at.desc())
        )
    )


@router.get("/{engagement_id}/campaigns/{campaign_id}", response_model=CampaignOut)
def get_campaign(
    campaign_id: str, access: EngagementAccess = Depends(require_engagement_role())
) -> Campaign:
    return _campaign(access, campaign_id)


@router.patch("/{engagement_id}/campaigns/{campaign_id}", response_model=CampaignOut)
def update(
    campaign_id: str,
    body: CampaignUpdate,
    access: EngagementAccess = Depends(require_engagement_role(*_WRITERS)),
) -> Campaign:
    campaign = _campaign(access, campaign_id)
    try:
        return campaigns.update_campaign(access, campaign, body)
    except campaigns.CampaignError as exc:
        raise HTTPException(exc.status, exc.detail) from None


@router.get("/{engagement_id}/campaigns/{campaign_id}/diffs", response_model=list[DiffOut])
def list_diffs(
    campaign_id: str,
    limit: int = Query(20, ge=1, le=100),
    access: EngagementAccess = Depends(require_engagement_role()),
) -> list[CampaignDiff]:
    _campaign(access, campaign_id)
    return list(
        access.session.scalars(
            select(CampaignDiff)
            .where(CampaignDiff.campaign_id == campaign_id)
            .order_by(CampaignDiff.created_at.desc(), CampaignDiff.id.desc())
            .limit(limit)
        )
    )


@router.get("/{engagement_id}/campaigns/{campaign_id}/runs", response_model=list[RunOut])
def list_campaign_runs(
    campaign_id: str,
    limit: int = Query(50, ge=1, le=200),
    access: EngagementAccess = Depends(require_engagement_role()),
) -> list[Run]:
    _campaign(access, campaign_id)
    return list(
        access.session.scalars(
            select(Run)
            .where(Run.campaign_id == campaign_id)
            .order_by(Run.created_at.desc())
            .limit(limit)
        )
    )
