"""Engagement report endpoints (spec 011). Any engagement member may read."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from .. import reports
from ..deps import EngagementAccess, require_engagement_role

router = APIRouter(prefix="/api/engagements", tags=["reports"])


@router.get("/{engagement_id}/report")
def get_report(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    return reports.build_report(access.session, access.engagement)


@router.get("/{engagement_id}/report.html", response_class=HTMLResponse)
def get_report_html(access: EngagementAccess = Depends(require_engagement_role())) -> HTMLResponse:
    report = reports.build_report(access.session, access.engagement)
    return HTMLResponse(reports.render_html(report))


@router.get("/{engagement_id}/report/navigator")
def get_navigator(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    return reports.navigator_layer(access.session, access.engagement)
