"""Engagement report endpoints (specs 011 and 013). Any engagement member may read and verify.

Exports (JSON and HTML) are audited with the ledger pin they issued; re-verification only reads.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from .. import reports
from ..deps import EngagementAccess, require_engagement_role
from ..schemas import ReportPin

router = APIRouter(prefix="/api/engagements", tags=["reports"])


def _export(access: EngagementAccess, fmt: str) -> dict:
    report = reports.build_report(access.session, access.engagement)
    reports.record_export(access.session, report, fmt=fmt, actor=access.user)
    access.session.commit()  # on record before it leaves; a failed audit write fails the export
    return report


@router.get("/{engagement_id}/report")
def get_report(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    return _export(access, "json")


@router.get("/{engagement_id}/report.html", response_class=HTMLResponse)
def get_report_html(access: EngagementAccess = Depends(require_engagement_role())) -> HTMLResponse:
    return HTMLResponse(reports.render_html(_export(access, "html")))


@router.post("/{engagement_id}/report/verify")
def post_report_verify(
    pin: ReportPin, access: EngagementAccess = Depends(require_engagement_role())
) -> dict:
    return reports.verify_pin(access.session, access.engagement, pin.root, pin.count)


@router.get("/{engagement_id}/report/navigator")
def get_navigator(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    return reports.navigator_layer(access.session, access.engagement)
