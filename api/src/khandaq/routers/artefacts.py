"""Content of ``model_artifact`` and ``dataset`` targets (spec 034): upload and status.

Owner-only upload, checked against the target's digest; any member reads the status. No route here
returns stored bytes or deletes them.
"""

from __future__ import annotations

import asyncio
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool

from .. import artefacts
from ..artefacts import ArtefactError
from ..deps import EngagementAccess, effective_role, require_engagement_role
from ..models import Target, TargetArtefact, User
from ..schemas import ArtefactOut
from ..settings import get_settings

router = APIRouter(prefix="/api/engagements", tags=["artefacts"])

# How long one upload's body may take to arrive: a trickled body must not hold a request, and
# the memory already received, for ever.
UPLOAD_SECONDS = 600.0


class _Uploads:
    """Uploads this process is holding in memory. Counted on the event loop only (the check and
    the increment have no await between them), so it needs no lock."""

    in_flight = 0


_uploads = _Uploads()


def _target(access: EngagementAccess, target_id: str) -> Target:
    target = access.session.get(Target, target_id)
    if target is None or target.engagement_id != access.engagement.id:
        raise HTTPException(404, "target not found in this engagement")
    return target


def _out(row: TargetArtefact) -> ArtefactOut:
    return ArtefactOut(
        target_id=row.target_id,
        sha256=row.sha256,
        bytes=row.bytes,
        # UTC whatever the database session's time zone is (timestamps are RFC 3339 UTC).
        stored_at=row.created_at.astimezone(dt.UTC),
    )


async def _body(request: Request, limit: int) -> bytes:
    """The request body, refused with 413 as soon as it passes ``limit`` bytes."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"the upload exceeds {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"the upload exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _still_owner(access: EngagementAccess) -> None:
    """The body may have taken minutes to arrive. Whoever was the owner when it began must still
    be one now: enabled, on the allow-list, and with the owner role on this engagement."""
    session, settings = access.session, get_settings()
    user = session.get(User, access.user.id, populate_existing=True)
    # The allow-list applies wherever sign-in is real; the development login has none.
    listed = settings.email_allowed(user.email) if user and settings.is_prod else True
    if user is None or user.disabled or not listed:
        raise HTTPException(403, "no access: this account can no longer upload")
    if effective_role(session, user, access.engagement.id) != "owner":
        raise HTTPException(403, "requires one of: owner")


def _store(access: EngagementAccess, target_id: str, content: bytes) -> tuple[ArtefactOut, bool]:
    session = access.session
    _still_owner(access)
    target = _target(access, target_id)
    try:
        row, created = artefacts.store_artefact(
            session, target, content, actor=access.user, settings=get_settings()
        )
    except ArtefactError as exc:
        if exc.audited:
            session.commit()  # the refusal's audit entry
        else:
            session.rollback()
        raise HTTPException(exc.status, exc.detail) from None
    session.commit()  # the row and its audit entry, or neither
    session.refresh(row)
    return _out(row), created


@router.put("/{engagement_id}/targets/{target_id}/artefact", response_model=ArtefactOut)
async def put_artefact(
    target_id: str,
    request: Request,
    response: Response,
    access: EngagementAccess = Depends(require_engagement_role("owner")),
) -> ArtefactOut:
    # Authorisation is decided; give the connection back while a possibly slow upload arrives.
    await run_in_threadpool(access.session.rollback)
    settings = get_settings()
    limit = settings.artefact_max_mb * 1024 * 1024
    # A slot is taken before a byte of the body is read and kept until the content is stored:
    # each upload holds its body in memory, so their number is what bounds the total.
    if _uploads.in_flight >= settings.artefact_max_uploads:
        raise HTTPException(
            429, "too many uploads at once; try again shortly", headers={"Retry-After": "30"}
        )
    _uploads.in_flight += 1
    try:
        try:
            async with asyncio.timeout(UPLOAD_SECONDS):
                content = await _body(request, limit)
        except TimeoutError:
            raise HTTPException(
                408, f"the upload did not arrive within {UPLOAD_SECONDS:.0f}s"
            ) from None
        out, created = await run_in_threadpool(_store, access, target_id, content)
    finally:
        _uploads.in_flight -= 1
    response.status_code = 201 if created else 200
    return out


@router.get("/{engagement_id}/targets/{target_id}/artefact", response_model=ArtefactOut)
def get_artefact(
    target_id: str,
    access: EngagementAccess = Depends(require_engagement_role()),
) -> ArtefactOut:
    row = artefacts.get(access.session, _target(access, target_id).id)
    if row is None:
        raise HTTPException(404, "no content is stored for this target")
    return _out(row)
