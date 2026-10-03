"""Download evidence bytes (spec 014). Owners, operators and analysts only (ADR-0006).

The API fetches the stored object, decrypts it (ADR-0016) and returns it only after it matches the
sealed ``evidence.sha256``. Every download is audited; a failed integrity check is audited as
``evidence.integrity_failed`` and answered 409, never with partial bytes.
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select

from .. import audit
from ..deps import EngagementAccess, require_engagement_role
from ..evidence_crypto import EvidenceKeyError, Keyring
from ..evidence_store import (
    EvidenceIntegrityError,
    EvidenceMissing,
    EvidenceStoreError,
    read_verified,
    store_from_settings,
)
from ..models import Evidence
from ..settings import get_settings

router = APIRouter(prefix="/api/engagements", tags=["evidence"])
log = logging.getLogger("khandaq.evidence")

_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


def _filename(evidence: Evidence) -> str:
    name = _UNSAFE_FILENAME.sub("_", evidence.object_key.rsplit("/", 1)[-1])[:100]
    return f"{evidence.id}-{name}"


@router.get("/{engagement_id}/evidence/{evidence_id}/content")
def download_evidence(
    evidence_id: str,
    access: EngagementAccess = Depends(require_engagement_role("owner", "operator", "analyst")),
) -> Response:
    session = access.session
    evidence = session.scalar(
        select(Evidence).where(
            Evidence.id == evidence_id, Evidence.engagement_id == access.engagement.id
        )
    )
    if evidence is None:  # unknown, or another engagement's evidence: no existence oracle
        raise HTTPException(404, "evidence not found")

    settings = get_settings()
    try:
        keyring: Keyring | None = Keyring.from_settings(settings)
    except EvidenceKeyError:
        keyring = None  # plaintext objects from before spec 014 stay readable
    try:
        data = read_verified(
            store_from_settings(settings), keyring, evidence.object_key, evidence.sha256
        )
    except EvidenceMissing:
        raise HTTPException(404, "no stored content for this evidence") from None
    except EvidenceStoreError as exc:  # the store is down or refusing us: not the caller's fault
        log.error(
            "evidence store unavailable", extra={"evidence_id": evidence.id, "error": str(exc)}
        )
        raise HTTPException(503, "evidence store unavailable; try again later") from None
    except EvidenceIntegrityError as exc:
        log.error(
            "evidence integrity check failed",
            extra={"evidence_id": evidence.id, "engagement_id": evidence.engagement_id},
        )
        audit.record(
            session,
            action="evidence.integrity_failed",
            actor=access.user,
            engagement_id=evidence.engagement_id,
            detail={"evidence_id": evidence.id, "reason": str(exc)},
        )
        session.commit()
        raise HTTPException(409, f"evidence failed its integrity check: {exc}") from None

    audit.record(
        session,
        action="evidence.downloaded",
        actor=access.user,
        engagement_id=evidence.engagement_id,
        detail={"evidence_id": evidence.id, "sha256": evidence.sha256, "bytes": len(data)},
    )
    session.commit()  # on record before the bytes leave
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{_filename(evidence)}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Khandaq-Evidence-Sha256": evidence.sha256,
        },
    )
