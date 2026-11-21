"""Content of ``model_artifact`` and ``dataset`` targets (spec 034): upload and status.

Owner-only upload, checked against the target's digest; any member reads the status. No route here
returns stored bytes or deletes them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool

from .. import artefacts
from ..artefacts import ArtefactError
from ..deps import EngagementAccess, require_engagement_role
from ..models import Target, TargetArtefact
from ..schemas import ArtefactOut
from ..settings import get_settings

router = APIRouter(prefix="/api/engagements", tags=["artefacts"])


def _target(access: EngagementAccess, target_id: str) -> Target:
    target = access.session.get(Target, target_id)
    if target is None or target.engagement_id != access.engagement.id:
        raise HTTPException(404, "target not found in this engagement")
    return target


def _out(row: TargetArtefact) -> ArtefactOut:
    return ArtefactOut(
        target_id=row.target_id, sha256=row.sha256, bytes=row.bytes, stored_at=row.created_at
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


def _store(access: EngagementAccess, target_id: str, content: bytes) -> tuple[ArtefactOut, bool]:
    session = access.session
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
    content = await _body(request, get_settings().artefact_max_mb * 1024 * 1024)
    out, created = await run_in_threadpool(_store, access, target_id, content)
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
