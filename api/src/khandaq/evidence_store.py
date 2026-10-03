"""Write-once evidence storage, encrypted at rest (spec 014, ADR-0016).

Two backends behind one protocol: the S3-compatible object store named by
``KHANDAQ_OBJECT_STORE_URL`` (RustFS in the bundled deployments) and, when that is empty, the
worker's evidence directory (spec 012). Neither ever overwrites an object. The service functions
here are the only way the app writes or reads evidence bytes:

- ``retain`` encrypts under the current key and stores the blob; an object already at the key is
  accepted only if it decrypts to the sha256 about to be sealed (a retried step), so sealed
  evidence is never replaced.
- ``read_verified`` returns bytes only after they match the sealed ``evidence.sha256``.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from .evidence_crypto import EvidenceDecryptError, Keyring, is_envelope

if TYPE_CHECKING:
    from .settings import Settings

log = logging.getLogger("khandaq.evidence")


class EvidenceExists(Exception):
    """An object is already stored at this key (stores never overwrite)."""


class EvidenceMissing(LookupError):
    """No object is stored at this key."""


class EvidenceConflict(ValueError):
    """The object already at a key holds different content than the evidence being sealed."""


class EvidenceIntegrityError(ValueError):
    """Stored bytes cannot be decrypted, or do not match their sealed sha256."""


class EvidenceStoreError(OSError):
    """The store failed (I/O or object-store error). The message never carries credentials."""


class EvidenceStore(Protocol):
    def put_new(self, object_key: str, blob: bytes) -> None:
        """Store ``blob`` at ``object_key``; raise ``EvidenceExists`` if anything is there."""

    def get(self, object_key: str) -> bytes:
        """Return the blob at ``object_key``; raise ``EvidenceMissing`` if there is none."""


class LocalEvidenceStore:
    """Files under a root directory, written to a temp name and hard-linked into place: the link
    fails if the key exists, so nothing is overwritten (spec 012). Each call gets its own temp file
    (``mkstemp``), so concurrent writers of one key never link each other's bytes."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, object_key: str) -> Path:
        path = (self.root / object_key).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise ValueError(f"evidence key {object_key!r} escapes the evidence directory")
        return path

    def put_new(self, object_key: str, blob: bytes) -> None:
        path = self._path(object_key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(blob)
            os.chmod(tmp, 0o440)
            os.link(tmp, path)
        except FileExistsError:
            raise EvidenceExists(object_key) from None
        finally:
            tmp.unlink(missing_ok=True)

    def get(self, object_key: str) -> bytes:
        try:
            return self._path(object_key).read_bytes()
        except FileNotFoundError:
            raise EvidenceMissing(object_key) from None


def _error_code(exc: Exception) -> str:
    """The S3 error code of a botocore error, or its class name (never its message or request)."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error") or {}
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        return str(error.get("Code") or status or type(exc).__name__)
    return type(exc).__name__


def _botocore_errors() -> tuple[type[Exception], ...]:
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:  # pragma: no cover - boto3 is a dependency
        return ()
    return (BotoCoreError, ClientError)


_NOT_FOUND = {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}
_PRECONDITION = {"412", "PreconditionFailed", "ConditionalRequestConflict"}


class S3EvidenceStore:
    """An S3-compatible bucket (RustFS, MinIO, AWS). The boto3 client is injected.

    Write-once: a ``HEAD`` first, then ``PUT`` with ``If-None-Match: *``, so a store that ignores
    the condition still never overwrites an object that already existed. The bucket is created on
    first use if missing, with versioning enabled where the store supports it."""

    def __init__(self, client: Any, bucket: str, prefix: str = "", region: str = "") -> None:
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region
        self._bucket_ready = False
        self._errors = _botocore_errors()

    def _key(self, object_key: str) -> str:
        return f"{self.prefix}/{object_key}" if self.prefix else object_key

    def _fail(self, action: str, exc: Exception) -> EvidenceStoreError:
        code = _error_code(exc)
        log.error("object store %s failed", action, extra={"bucket": self.bucket, "code": code})
        return EvidenceStoreError(f"object store {action} failed: {code}")

    def _ensure_bucket(self) -> None:
        if self._bucket_ready:
            return
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except self._errors as exc:
            if _error_code(exc) not in _NOT_FOUND:
                raise self._fail("bucket check", exc) from None
            self._create_bucket()
        self._bucket_ready = True

    def _create_bucket(self) -> None:
        kwargs: dict[str, Any] = {"Bucket": self.bucket}
        if self.region and self.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
        try:
            self.client.create_bucket(**kwargs)
        except self._errors as exc:
            if _error_code(exc) not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                raise self._fail("bucket create", exc) from None
        log.info("created evidence bucket", extra={"bucket": self.bucket})
        try:
            self.client.put_bucket_versioning(
                Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"}
            )
        except self._errors as exc:
            log.warning(
                "could not enable bucket versioning",
                extra={"bucket": self.bucket, "code": _error_code(exc)},
            )

    def put_new(self, object_key: str, blob: bytes) -> None:
        self._ensure_bucket()
        key = self._key(object_key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except self._errors as exc:
            if _error_code(exc) not in _NOT_FOUND:
                raise self._fail("head", exc) from None
        else:
            raise EvidenceExists(object_key)
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=blob,
                IfNoneMatch="*",
                ContentType="application/octet-stream",
            )
        except self._errors as exc:
            if _error_code(exc) in _PRECONDITION:
                raise EvidenceExists(object_key) from None
            raise self._fail("put", exc) from None

    def get(self, object_key: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(object_key))
            return bytes(response["Body"].read())
        except self._errors as exc:
            if _error_code(exc) in _NOT_FOUND:
                raise EvidenceMissing(object_key) from None
            raise self._fail("get", exc) from None


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _plaintext(keyring: Keyring | None, object_key: str, blob: bytes) -> bytes:
    """Decrypt an envelope; a blob without the ADR-0016 header predates spec 014 (plaintext)."""
    if not is_envelope(blob):
        return blob
    if keyring is None:
        raise EvidenceIntegrityError("evidence is encrypted but no evidence key is configured")
    try:
        return keyring.decrypt(object_key, blob)
    except EvidenceDecryptError as exc:
        raise EvidenceIntegrityError(str(exc)) from exc


def retain(
    store: EvidenceStore, keyring: Keyring, object_key: str, content: bytes, sha256: str
) -> None:
    """Encrypt and store evidence bytes write-once before they are sealed (spec 014 §1–2)."""
    if _sha256(content) != sha256:
        raise EvidenceConflict(f"evidence {object_key!r} does not match the hash to be sealed")
    try:
        store.put_new(object_key, keyring.encrypt(object_key, content))
    except EvidenceExists:
        existing = store.get(object_key)
        try:
            same = _sha256(_plaintext(keyring, object_key, existing)) == sha256
        except EvidenceIntegrityError:
            same = False
        if not same:
            raise EvidenceConflict(
                f"evidence {object_key!r} already exists with other content"
            ) from None
        log.info("evidence already stored; identical retry accepted", extra={"key": object_key})


def read_verified(
    store: EvidenceStore, keyring: Keyring | None, object_key: str, sha256: str
) -> bytes:
    """Return the evidence plaintext only if it matches the sealed sha256 (spec 014 §5)."""
    data = _plaintext(keyring, object_key, store.get(object_key))
    if _sha256(data) != sha256:
        raise EvidenceIntegrityError("stored evidence does not match its sealed hash")
    return data


def parse_store_url(url: str) -> tuple[str, str] | None:
    """``s3://bucket[/prefix]`` → (bucket, prefix); empty → None (local store); else ValueError."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme != "s3" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("KHANDAQ_OBJECT_STORE_URL must be empty or s3://<bucket>[/<prefix>]")
    return parsed.netloc, parsed.path.strip("/")


@functools.lru_cache(maxsize=4)
def _s3_store(
    bucket: str, prefix: str, endpoint: str, region: str, access_key: str, secret_key: str
) -> S3EvidenceStore:
    import boto3  # lazy: only deployments with an object store pay for the import
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=endpoint or None,
        region_name=region or "us-east-1",
        aws_access_key_id=access_key or None,
        aws_secret_access_key=secret_key or None,
        # Path-style addressing: RustFS / MinIO serve buckets under the endpoint's path.
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 3}),
    )
    return S3EvidenceStore(client, bucket, prefix, region)


def store_from_settings(settings: Settings) -> EvidenceStore:
    """The configured store (spec 014 §4). The S3 client is built once per configuration."""
    target = parse_store_url(settings.object_store_url)
    if target is None:
        return LocalEvidenceStore(Path(settings.evidence_dir))
    bucket, prefix = target
    return _s3_store(
        bucket,
        prefix,
        settings.object_store_endpoint,
        settings.object_store_region,
        settings.object_store_access_key_id,
        settings.object_store_secret_access_key,
    )
