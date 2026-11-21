"""Stored content of ``model_artifact`` and ``dataset`` targets (spec 034).

Such a target names its content by digest, and the scope lock matches it by that digest. This
module is the only way the content itself gets into Khandaq and back out: an upload is stored only
if its SHA-256 is the digest the target declares, as an ADR-0016 envelope in the evidence store,
write-once; and it is handed back only after it matches that digest again. Khandaq never fetches
content from a target's ``location``.

Stored content gives a target no permission: the scope lock decides every run as before. No
message raised or logged here contains artefact bytes.
"""

from __future__ import annotations

import hashlib
import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .evidence_crypto import EvidenceDecryptError, EvidenceKeyError, Keyring, is_envelope
from .evidence_store import (
    EvidenceConflict,
    EvidenceMissing,
    EvidenceStoreError,
    retain,
    store_from_settings,
)
from .ledger import lock_engagement
from .models import Engagement, Target, TargetArtefact, User
from .settings import Settings

log = logging.getLogger("khandaq.artefacts")

ARTEFACT_TYPES = ("model_artifact", "dataset")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class ArtefactError(Exception):
    """An artefact request cannot be honoured. ``status`` is the HTTP status for the API.
    ``audited`` says an audit entry was added to the session and must be committed with the
    refusal."""

    def __init__(self, status: int, detail: str, *, audited: bool = False):
        self.status = status
        self.detail = detail
        self.audited = audited
        super().__init__(detail)


def sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def object_key(engagement_id: str, target_id: str, digest: str) -> str:
    """Where a target's content lives in the store. The envelope is bound to this key, so a blob
    copied to another engagement's or target's key does not decrypt."""
    return f"artefacts/{engagement_id}/{target_id}/{digest.removeprefix('sha256:')}"


def declared_digest(target: Target) -> str:
    """The digest a target's content must have, or a 409 saying why it can hold none."""
    if target.type not in ARTEFACT_TYPES:
        raise ArtefactError(409, f"a {target.type} target holds no content")
    digest = target.spec.get("digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ArtefactError(
            409,
            "content can be stored only for a target whose 'digest' is "
            "'sha256:' followed by 64 lower-case hex characters",
        )
    return digest


def get(session: Session, target_id: str) -> TargetArtefact | None:
    return session.scalar(select(TargetArtefact).where(TargetArtefact.target_id == target_id))


def by_target(session: Session, engagement_id: str) -> dict[str, TargetArtefact]:
    """The engagement's stored content by target id (for the ``has_artefact`` flag)."""
    rows = session.scalars(
        select(TargetArtefact).where(TargetArtefact.engagement_id == engagement_id)
    )
    return {row.target_id: row for row in rows}


def _keyring(settings: Settings) -> Keyring:
    try:
        return Keyring.from_settings(settings)
    except EvidenceKeyError:
        raise ArtefactError(
            503, "no evidence key is configured; content cannot be stored"
        ) from None


def store_artefact(
    session: Session, target: Target, content: bytes, *, actor: User, settings: Settings
) -> tuple[TargetArtefact, bool]:
    """Store ``content`` for ``target`` if its SHA-256 is the target's digest (spec 034 §1–5).

    Returns the row and whether it is new. The caller commits: the row and its audit entry, or,
    for an ``ArtefactError`` marked ``audited``, the entry that records the refusal.
    """
    # Under the lock that closing takes, so an upload cannot commit behind a concurrent close, and
    # two first uploads for one target do not both insert.
    lock_engagement(session, target.engagement_id)
    engagement = session.get(Engagement, target.engagement_id, populate_existing=True)
    if engagement is None or engagement.state == "closed":
        raise ArtefactError(409, "a closed engagement takes no content")
    expected = declared_digest(target)
    if not content:
        raise ArtefactError(422, "the upload is empty")
    actual = sha256_digest(content)
    if actual != expected:
        audit.record(
            session,
            action="target.artefact_rejected",
            actor=actor,
            engagement_id=target.engagement_id,
            detail={
                "target_id": target.id,
                "type": target.type,
                "expected": expected,
                "received": actual,
                "bytes": len(content),
            },
        )
        raise ArtefactError(
            422,
            f"the upload's SHA-256 is {actual}, not the target's digest {expected}",
            audited=True,
        )
    existing = get(session, target.id)
    if existing is not None:
        return existing, False
    if settings.is_prod and not settings.object_store_url:
        # Without the object store the API would write into its own evidence directory, which the
        # worker, another container, never sees: the content would be recorded and unusable.
        raise ArtefactError(
            503, "content uploads need the object store (KHANDAQ_OBJECT_STORE_URL is empty)"
        )
    key = object_key(target.engagement_id, target.id, expected)
    try:
        retain(store_from_settings(settings), _keyring(settings), key, content, expected)
    except EvidenceConflict:
        log.error("stored artefact differs from its digest", extra={"target_id": target.id})
        raise ArtefactError(
            409, "other content is already stored under this target's digest"
        ) from None
    except EvidenceStoreError as exc:
        log.error("artefact store unavailable", extra={"target_id": target.id, "error": str(exc)})
        raise ArtefactError(503, "the evidence store is unavailable; try again later") from None
    row = TargetArtefact(
        target_id=target.id,
        engagement_id=target.engagement_id,
        sha256=expected,
        bytes=len(content),
        object_key=key,
        stored_by_user_id=actor.id,
    )
    session.add(row)
    audit.record(
        session,
        action="target.artefact_stored",
        actor=actor,
        engagement_id=target.engagement_id,
        detail={
            "target_id": target.id,
            "type": target.type,
            "sha256": expected,
            "bytes": len(content),
        },
    )
    return row, True


def read_artefact(session: Session, target: Target, settings: Settings) -> bytes:
    """The stored content of ``target``, only after it matches the digest the target declares now
    and the one recorded at upload (spec 034 §6). Raises ``ArtefactError`` otherwise: there is no
    partial result and no fallback to unverified or unencrypted bytes."""
    expected = declared_digest(target)
    row = get(session, target.id)
    if row is None:
        raise ArtefactError(404, "no content is stored for this target")
    if row.sha256 != expected:
        raise ArtefactError(409, "the stored content is not the content the target names")
    try:
        blob = store_from_settings(settings).get(row.object_key)
    except EvidenceMissing:
        raise ArtefactError(404, "the stored content is missing from the evidence store") from None
    except EvidenceStoreError as exc:
        log.error("artefact store unavailable", extra={"target_id": target.id, "error": str(exc)})
        raise ArtefactError(503, "the evidence store is unavailable; try again later") from None
    if not is_envelope(blob):
        raise ArtefactError(409, "the stored content is not encrypted; it is not used")
    try:
        content = _keyring(settings).decrypt(row.object_key, blob)
    except EvidenceDecryptError:
        raise ArtefactError(409, "the stored content cannot be decrypted") from None
    if sha256_digest(content) != expected:
        raise ArtefactError(409, "the stored content does not match the target's digest")
    return content
