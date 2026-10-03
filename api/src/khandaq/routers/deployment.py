"""``GET /api/deployment`` (spec 023): the API's and each worker's settings summary. Organisation
admins only: it shows the deployment's shape (never a secret), not engagement data."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import __version__
from ..db import schema_revision
from ..deployment import settings_summary, workers
from ..deps import current_user, get_session
from ..models import User
from ..settings import get_settings

router = APIRouter(prefix="/api", tags=["deployment"])


@router.get("/deployment")
def deployment_status(
    user: User = Depends(current_user), session: Session = Depends(get_session)
) -> dict:
    if user.org_role != "admin":
        raise HTTPException(403, "organisation admins only")
    settings = get_settings()
    return {
        "checked_at": dt.datetime.now(dt.UTC),
        "api": {
            "app_version": __version__,
            "schema_revision": schema_revision(settings),
            "summary": settings_summary(settings),
        },
        "workers": workers(session),
    }
