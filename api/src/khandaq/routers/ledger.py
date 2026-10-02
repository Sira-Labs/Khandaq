"""Read and verify the evidence ledger (spec 004).

Evidence is written on the run path (spec 005); these endpoints expose the chain and its
verification so a reviewer (or a report) can confirm the record is intact. Any member may read.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import ledger as ledger_svc
from ..deps import EngagementAccess, require_engagement_role

router = APIRouter(prefix="/api/engagements", tags=["ledger"])


@router.get("/{engagement_id}/ledger")
def get_ledger(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    session, eng_id = access.session, access.engagement.id
    return {
        "entries": ledger_svc.load_chain(session, eng_id),
        "root": ledger_svc.root(session, eng_id),
        "verify": ledger_svc.verify_chain(session, eng_id),
    }


@router.post("/{engagement_id}/ledger/verify")
def post_verify(access: EngagementAccess = Depends(require_engagement_role())) -> dict:
    return ledger_svc.verify_chain(access.session, access.engagement.id)
