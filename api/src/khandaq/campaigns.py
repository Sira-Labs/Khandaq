"""Campaigns: a run template the worker re-runs on an interval (spec 016, ADR-0017).

Creating or changing a campaign is audited, and the template is checked against the scope lock up
front. The worker's loop calls ``schedule_due``, which turns each due campaign into a run through
``runs.queue_run``, so a scheduled run passes the same scope lock (and its claim-time re-check)
and leaves the same audit trail as a run a person starts. Missed windows are not replayed, and a
campaign whose last run is still in flight gets no new one.
"""

from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .adapters import get_manifest
from .deps import EngagementAccess
from .models import Campaign, Engagement, Run, Target, User
from .runs import queue_run, scope_refusal
from .schemas import CampaignCreate, CampaignUpdate
from .settings import get_settings

log = logging.getLogger("khandaq.campaigns")

SCHEDULE_BATCH = 20


class CampaignError(Exception):
    """A client error creating or changing a campaign (mapped to HTTP by the router)."""

    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _check_interval(minutes: int) -> None:
    floor = get_settings().campaign_min_interval_minutes
    if minutes < floor:
        raise CampaignError(422, f"interval_minutes must be at least {floor}")


def _view(c: Campaign) -> dict:
    return {
        "name": c.name,
        "adapter": c.adapter,
        "target_id": c.target_id,
        "params": c.params,
        "interval_minutes": c.interval_minutes,
        "enabled": c.enabled,
    }


def create_campaign(access: EngagementAccess, body: CampaignCreate) -> Campaign:
    """Validate, scope-check and store a campaign (spec 016 §1). Commits."""
    session, eng = access.session, access.engagement
    if get_manifest(body.adapter) is None:
        raise CampaignError(422, f"unknown adapter '{body.adapter}'")
    target = session.get(Target, body.target_id)
    if target is None or target.engagement_id != eng.id:
        raise CampaignError(404, "target not found in this engagement")
    _check_interval(body.interval_minutes)
    if eng.state != "active":
        raise CampaignError(409, f"engagement is '{eng.state}', not active")

    reason = scope_refusal(session, eng, target, body.params)
    if reason is not None:
        audit.record(
            session,
            action="campaign.rejected",
            actor=access.user,
            engagement_id=eng.id,
            detail={"name": body.name, "adapter": body.adapter, "reason": reason},
        )
        session.commit()
        raise CampaignError(422, f"out of scope: {reason}")

    now = _now()
    start = body.start_at if body.start_at is not None and body.start_at > now else now
    campaign = Campaign(
        engagement_id=eng.id,
        name=body.name,
        adapter=body.adapter,
        target_id=target.id,
        params=body.params,
        interval_minutes=body.interval_minutes,
        enabled=True,
        next_run_at=start,
        created_by=access.user.id,
    )
    session.add(campaign)
    session.flush()
    audit.record(
        session,
        action="campaign.created",
        actor=access.user,
        engagement_id=eng.id,
        detail={"campaign_id": campaign.id, **_view(campaign), "next_run_at": start.isoformat()},
    )
    session.commit()
    session.refresh(campaign)
    return campaign


def update_campaign(access: EngagementAccess, campaign: Campaign, body: CampaignUpdate) -> Campaign:
    """Enable/disable or change the interval (spec 016 §5). Audited with before/after. Commits."""
    session = access.session
    if access.engagement.state == "closed":
        raise CampaignError(409, "cannot change a campaign of a closed engagement")
    if body.interval_minutes is not None:
        _check_interval(body.interval_minutes)
    before = _view(campaign)
    if body.enabled is not None:
        campaign.enabled = body.enabled
    if body.interval_minutes is not None:
        campaign.interval_minutes = body.interval_minutes
    after = _view(campaign)
    if after != before:
        campaign.updated_at = _now()
        audit.record(
            session,
            action="campaign.updated",
            actor=access.user,
            engagement_id=campaign.engagement_id,
            detail={"campaign_id": campaign.id, "before": before, "after": after},
        )
    session.commit()
    session.refresh(campaign)
    return campaign


def _disable_closed(session: Session, campaign: Campaign, actor: User | None) -> None:
    before = _view(campaign)
    campaign.enabled = False
    campaign.updated_at = _now()
    audit.record(
        session,
        action="campaign.updated",
        actor=actor,
        engagement_id=campaign.engagement_id,
        detail={
            "campaign_id": campaign.id,
            "before": before,
            "after": _view(campaign),
            "reason": "engagement closed",
        },
    )


def disable_for_closed_engagement(session: Session, engagement_id: str, actor: User) -> int:
    """Disable every enabled campaign of an engagement being closed, each audited (PR #36 review).

    A closed engagement's campaigns cannot be changed through the API, so one left enabled would
    keep producing a rejected run every window. Called by engagement close. Caller commits."""
    campaigns = session.scalars(
        select(Campaign)
        .where(Campaign.engagement_id == engagement_id, Campaign.enabled.is_(True))
        .order_by(Campaign.id)
        .with_for_update()
    ).all()
    for campaign in campaigns:
        _disable_closed(session, campaign, actor)
    return len(campaigns)


def _in_flight(session: Session, campaign_id: str) -> bool:
    return (
        session.scalar(
            select(Run.id)
            .where(Run.campaign_id == campaign_id, Run.state.in_(("queued", "running")))
            .limit(1)
        )
        is not None
    )


def schedule_due(session: Session, now: dt.datetime | None = None) -> int:
    """Worker: create runs for due campaigns (spec 016 §2). Returns how many campaigns were due.

    ``FOR UPDATE SKIP LOCKED`` hands each due campaign to one worker; everything for a batch
    commits together, so a window is either scheduled and advanced, or neither."""
    now = now or _now()
    due = list(
        session.scalars(
            select(Campaign)
            .where(Campaign.enabled.is_(True), Campaign.next_run_at <= now)
            .order_by(Campaign.next_run_at, Campaign.id)
            .with_for_update(skip_locked=True)
            .limit(SCHEDULE_BATCH)
        )
    )
    if not due:
        session.rollback()
        return 0
    for campaign in due:
        detail: dict = {"campaign_id": campaign.id}
        engagement = session.get(Engagement, campaign.engagement_id)
        target = session.get(Target, campaign.target_id)
        if engagement is None or target is None:  # pragma: no cover - never deleted
            raise RuntimeError(f"campaign {campaign.id} lost its engagement or target")
        if engagement.state == "closed":
            # A row from before close disabled campaigns. Only the row this batch already holds
            # is touched: locking its siblings could deadlock with another worker's batch.
            _disable_closed(session, campaign, actor=None)
            continue
        if _in_flight(session, campaign.id):
            detail["skipped"] = "the previous run is still queued or running"
        else:
            try:
                run = queue_run(
                    session,
                    engagement,
                    target,
                    campaign.adapter,
                    campaign.params or {},
                    actor=None,
                    campaign_id=campaign.id,
                )
            except ValueError as exc:  # the adapter was removed since the campaign was created
                detail["skipped"] = str(exc)
            else:
                detail["run_id"] = run.id
                if run.state == "rejected":
                    detail["rejected"] = run.reject_reason
        campaign.next_run_at = now + dt.timedelta(minutes=campaign.interval_minutes)
        audit.record(
            session,
            action="campaign.run_scheduled",
            engagement_id=campaign.engagement_id,
            detail=detail,
        )
        log.info("campaign scheduled", extra=detail)
    session.commit()
    return len(due)
