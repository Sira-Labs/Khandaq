"""Per-run target credentials (spec 028, ADR-0006, ADR-0019).

One write-only secret per target, for example the API key of an in-scope LLM endpoint. It is stored
as an ADR-0016 envelope under ``KHANDAQ_CREDENTIAL_KEY`` (a key separate from the evidence key),
decrypted only by the worker when a run starts, handed to the sandboxed adapter as one environment
value, and replaced by ``[REDACTED:target-credential]`` in everything the run returns before any
of it is hashed or recorded. Nothing in this module returns a stored value to an API caller, and
no message it raises contains one.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import audit
from .adapters import AdapterManifest
from .credential_values import CredentialError, validate_value
from .evidence_crypto import MIN_KEY_CHARS, EvidenceDecryptError, EvidenceKeyError, Keyring
from .ledger import lock_engagement
from .models import AuditLog, Engagement, Run, Target, TargetCredential, User
from .scope import ScopeError, network_endpoint
from .settings import Settings

# The spec fields a target's URLs live in; kept equal to the scope lock's by a test.
URL_FIELDS = ("url", "base_url", "endpoint")
_ENCRYPTED_SCHEMES = frozenset({"https", "wss"})

_NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*", re.IGNORECASE)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


CredentialUse = Literal["injected", "none", "not_accepted"]


# --- rules ----------------------------------------------------------------------------------------


def transport_problem(target_type: str, spec: dict) -> str | None:
    """Why a credential must not travel to this target, or ``None`` (spec 028 §3).

    Refused: a target without a usable network endpoint, and plain ``http``/``ws`` to a host with a
    dot in its name. A single-label host is a service name inside the deployment network.
    """
    try:
        host, _port = network_endpoint(target_type, spec)
    except ScopeError as exc:
        return f"the target has no usable network endpoint: {exc}"
    if _NUMERIC_HOST.fullmatch(host) or _is_ip(host):
        # A bare address names no service of the deployment, a numeric host (`134744072`) is an
        # address in disguise, and the sandbox runs no IP-literal target anyway.
        return "a credential needs a target named by host name, not by address"
    schemes = {urlsplit(str(spec[field])).scheme.lower() for field in URL_FIELDS if spec.get(field)}
    if schemes <= _ENCRYPTED_SCHEMES:
        return None
    if "." in host:
        return (
            "a credential is not sent over plain http to a public-looking host; "
            "use an https URL for this target"
        )
    return None


# --- storage --------------------------------------------------------------------------------------


def enabled(settings: Settings) -> bool:
    return bool(settings.credential_key)


def keyring(settings: Settings) -> Keyring:
    """The credential keyring; a 503 when the feature is off or the key is unusable."""
    if not settings.credential_key:
        raise CredentialError(503, "target credentials are not enabled on this deployment")
    previous = [k.strip() for k in settings.credential_previous_keys.split(",") if k.strip()]
    try:
        return Keyring.from_secrets(settings.credential_key, previous)
    except EvidenceKeyError as exc:
        raise CredentialError(
            503, f"KHANDAQ_CREDENTIAL_KEY and its retired keys need {MIN_KEY_CHARS} characters"
        ) from exc


def _object_key(engagement_id: str, target_id: str, version: int) -> str:
    """The envelope's AAD: a blob moved to another engagement, target or version fails to open."""
    return f"credential/{engagement_id}/{target_id}/{version}"


def get(session: Session, target_id: str) -> TargetCredential | None:
    return session.scalars(
        select(TargetCredential).where(TargetCredential.target_id == target_id)
    ).first()


def by_target(session: Session, engagement_id: str) -> dict[str, TargetCredential]:
    """The engagement's credentials by target id (for the ``has_credential`` flag)."""
    rows = session.scalars(
        select(TargetCredential).where(TargetCredential.engagement_id == engagement_id)
    )
    return {row.target_id: row for row in rows}


def lock_for_change(session: Session, engagement: Engagement) -> Engagement:
    """Serialise credential changes with closing the engagement, and reload its state.

    Without it a `PUT` that read the engagement as active could commit after a concurrent close
    had deleted the credentials, leaving a closed engagement with a live secret; and two first
    `PUT`s for one target would both insert. Held until the transaction ends.
    """
    lock_engagement(session, engagement.id)
    session.refresh(engagement)
    return engagement


def set_credential(
    session: Session, target: Target, value: object, *, actor: User, settings: Settings
) -> TargetCredential:
    """Store or replace the target's credential and audit it in the caller's transaction. The
    caller holds ``lock_for_change``."""
    ring = keyring(settings)
    secret = validate_value(value)
    problem = transport_problem(target.type, target.spec)
    if problem is not None:
        raise CredentialError(422, problem)
    row = get(session, target.id)
    rotated = row is not None
    version = row.version + 1 if row is not None else 1
    blob = ring.encrypt(_object_key(target.engagement_id, target.id, version), secret.encode())
    if row is None:
        row = TargetCredential(
            target_id=target.id,
            engagement_id=target.engagement_id,
            ciphertext=blob,
            version=version,
            set_by_user_id=actor.id,
        )
        session.add(row)
    else:
        row.ciphertext, row.version, row.set_by_user_id = blob, version, actor.id
        row.updated_at = dt.datetime.now(dt.UTC)
    audit.record(
        session,
        action="target.credential_set",
        actor=actor,
        engagement_id=target.engagement_id,
        detail={"target_id": target.id, "version": version, "rotated": rotated},
    )
    session.flush()
    return row


def clear_credential(
    session: Session, row: TargetCredential, *, actor: User | None, reason: str
) -> None:
    """Delete one credential outright and audit that it happened; the caller commits."""
    audit.record(
        session,
        action="target.credential_cleared",
        actor=actor,
        engagement_id=row.engagement_id,
        detail={"target_id": row.target_id, "reason": reason},
    )
    session.execute(delete(TargetCredential).where(TargetCredential.id == row.id))


def clear_for_closed_engagement(session: Session, engagement_id: str, *, actor: User) -> int:
    """A closed engagement holds no live secret (spec 028 §5); the caller commits."""
    rows = list(by_target(session, engagement_id).values())
    for row in rows:
        clear_credential(session, row, actor=actor, reason="engagement closed")
    return len(rows)


# --- injection ------------------------------------------------------------------------------------


def planned_use(session: Session, target: Target, manifest: AdapterManifest) -> CredentialUse:
    """What ``run.started`` records: whether this run will carry the target's credential."""
    if get(session, target.id) is None:
        return "none"
    return "injected" if manifest.accepts_credential else "not_accepted"


def recorded_use(session: Session, run: Run) -> str | None:
    """The ``credential`` value this run's ``run.started`` entry recorded."""
    entry = session.scalars(
        select(AuditLog)
        .where(
            AuditLog.engagement_id == run.engagement_id,
            AuditLog.action == "run.started",
            AuditLog.detail["run_id"].astext == run.id,
        )
        .order_by(AuditLog.at.desc())
        .limit(1)
    ).first()
    return None if entry is None else entry.detail.get("credential")


def load_for_run(session: Session, run: Run, target: Target, settings: Settings) -> str | None:
    """The plaintext credential for this run, or ``None`` when it runs without one.

    Only the credential of the run's own target is ever loaded, and only when ``run.started``
    recorded ``injected``: the audit trail and what happened cannot disagree. A credential that
    vanished since, cannot be decrypted, or may not travel to the target fails the run; nothing
    falls back to running without it.
    """
    if recorded_use(session, run) != "injected":
        return None
    row = get(session, target.id)
    if row is None:
        raise CredentialError(409, "the target's credential was removed after the run started")
    problem = transport_problem(target.type, target.spec)
    if problem is not None:
        raise CredentialError(422, problem)
    try:
        ring = keyring(settings)
        plain = ring.decrypt(
            _object_key(row.engagement_id, row.target_id, row.version), bytes(row.ciphertext)
        )
    except (CredentialError, EvidenceDecryptError) as exc:
        raise CredentialError(
            500, "the target's credential cannot be decrypted with the configured key"
        ) from exc
    return validate_value(plain.decode("utf-8", "replace"))
