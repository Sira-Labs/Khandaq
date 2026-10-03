"""Write-once, encrypted evidence storage (spec 014 §1–5). No database, no network: the S3 store
runs against an in-memory fake of the boto3 client. Synthetic keys and data only."""

from __future__ import annotations

import hashlib
import io
import json

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from khandaq.evidence_crypto import Keyring
from khandaq.evidence_store import (
    EvidenceConflict,
    EvidenceExists,
    EvidenceIntegrityError,
    EvidenceMissing,
    EvidenceStoreError,
    LocalEvidenceStore,
    S3EvidenceStore,
    parse_store_url,
    read_verified,
    retain,
    store_from_settings,
)
from khandaq.settings import Settings

RING = Keyring.from_secrets("synthetic-evidence-key-for-tests-0001")
KEY = "eng_1/run_1/report.jsonl"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _client_error(code: str, status: int, op: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "synthetic"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        op,
    )


class FakeS3:
    """The boto3 S3 client calls the store makes, over a dict. ``honours_condition=False`` models a
    store that ignores If-None-Match (the HEAD check must still prevent overwrites)."""

    def __init__(self, bucket_exists: bool = True, honours_condition: bool = True) -> None:
        self.bucket_exists = bucket_exists
        self.honours_condition = honours_condition
        self.objects: dict[str, bytes] = {}
        self.calls: list[tuple[str, dict]] = []
        self.versioning: dict | None = None

    def head_bucket(self, **kw):
        self.calls.append(("head_bucket", kw))
        if not self.bucket_exists:
            raise _client_error("404", 404, "HeadBucket")

    def create_bucket(self, **kw):
        self.calls.append(("create_bucket", kw))
        self.bucket_exists = True

    def put_bucket_versioning(self, **kw):
        self.calls.append(("put_bucket_versioning", kw))
        self.versioning = kw["VersioningConfiguration"]

    def head_object(self, **kw):
        self.calls.append(("head_object", kw))
        if kw["Key"] not in self.objects:
            raise _client_error("404", 404, "HeadObject")
        return {}

    def put_object(self, **kw):
        self.calls.append(("put_object", {k: v for k, v in kw.items() if k != "Body"}))
        if self.honours_condition and kw.get("IfNoneMatch") == "*" and kw["Key"] in self.objects:
            raise _client_error("PreconditionFailed", 412, "PutObject")
        self.objects[kw["Key"]] = kw["Body"]

    def get_object(self, **kw):
        self.calls.append(("get_object", kw))
        if kw["Key"] not in self.objects:
            raise _client_error("NoSuchKey", 404, "GetObject")
        return {"Body": io.BytesIO(self.objects[kw["Key"]])}


# --- local store -----------------------------------------------------------------------------


def test_local_store_is_write_once(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    store.put_new(KEY, b"one")
    with pytest.raises(EvidenceExists):
        store.put_new(KEY, b"two")
    assert store.get(KEY) == b"one"
    assert json.dumps(sorted(p.name for p in (tmp_path / "eng_1/run_1").iterdir())) == (
        '["report.jsonl"]'
    )  # no temp file left behind
    with pytest.raises(EvidenceMissing):
        store.get("eng_1/run_1/other")
    with pytest.raises(ValueError, match="escapes"):
        store.put_new("../outside.txt", b"x")


def test_retain_stores_ciphertext_and_accepts_an_identical_retry(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    retain(store, RING, KEY, b"tool output", sha(b"tool output"))
    first = (tmp_path / KEY).read_bytes()
    assert first.startswith(b"KHQE") and b"tool output" not in first
    retain(store, RING, KEY, b"tool output", sha(b"tool output"))  # a retried step
    assert (tmp_path / KEY).read_bytes() == first  # not overwritten
    assert read_verified(store, RING, KEY, sha(b"tool output")) == b"tool output"


def test_retain_refuses_other_content_under_an_existing_key(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    retain(store, RING, KEY, b"one", sha(b"one"))
    with pytest.raises(EvidenceConflict, match="other content"):
        retain(store, RING, KEY, b"two", sha(b"two"))
    assert read_verified(store, RING, KEY, sha(b"one")) == b"one"


def test_retain_refuses_bytes_that_do_not_match_the_hash(tmp_path):
    with pytest.raises(EvidenceConflict, match="does not match"):
        retain(LocalEvidenceStore(tmp_path), RING, KEY, b"one", sha(b"two"))
    assert not (tmp_path / KEY).exists()


def test_read_verified_detects_tampering(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    retain(store, RING, KEY, b"tool output", sha(b"tool output"))
    path = tmp_path / KEY
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01
    path.chmod(0o640)
    path.write_bytes(bytes(blob))
    with pytest.raises(EvidenceIntegrityError, match="authentication"):
        read_verified(store, RING, KEY, sha(b"tool output"))


def test_read_verified_needs_the_key_for_an_envelope(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    retain(store, RING, KEY, b"tool output", sha(b"tool output"))
    with pytest.raises(EvidenceIntegrityError, match="no evidence key"):
        read_verified(store, None, KEY, sha(b"tool output"))


def test_legacy_plaintext_is_served_only_when_it_matches_the_seal(tmp_path):
    store = LocalEvidenceStore(tmp_path)
    store.put_new(KEY, b'{"probe": "legacy"}')  # retained by spec 012, before encryption
    assert read_verified(store, None, KEY, sha(b'{"probe": "legacy"}')) == b'{"probe": "legacy"}'
    with pytest.raises(EvidenceIntegrityError, match="sealed hash"):
        read_verified(store, RING, KEY, sha(b"something else"))


# --- S3 store --------------------------------------------------------------------------------


def test_s3_put_heads_then_writes_conditionally_under_the_prefix():
    fake = FakeS3()
    store = S3EvidenceStore(fake, "khandaq-evidence", prefix="/stg/")
    retain(store, RING, KEY, b"tool output", sha(b"tool output"))
    ops = [(op, kw.get("Key")) for op, kw in fake.calls]
    assert ops == [
        ("head_bucket", None),
        ("head_object", f"stg/{KEY}"),
        ("put_object", f"stg/{KEY}"),
    ]
    put = fake.calls[-1][1]
    assert put["IfNoneMatch"] == "*" and put["Bucket"] == "khandaq-evidence"
    assert fake.objects[f"stg/{KEY}"].startswith(b"KHQE")
    assert read_verified(store, RING, KEY, sha(b"tool output")) == b"tool output"


def test_s3_never_overwrites_even_when_the_condition_is_ignored():
    fake = FakeS3(honours_condition=False)
    store = S3EvidenceStore(fake, "bucket")
    store.put_new(KEY, b"first")
    with pytest.raises(EvidenceExists):
        store.put_new(KEY, b"second")
    assert fake.objects[KEY] == b"first"
    assert [op for op, _ in fake.calls].count("put_object") == 1


def test_s3_precondition_failure_means_exists():
    fake = FakeS3()
    store = S3EvidenceStore(fake, "bucket")
    store._bucket_ready = True
    fake.head_object = lambda **kw: (_ for _ in ()).throw(_client_error("404", 404, "HeadObject"))
    fake.objects[KEY] = b"raced in between"
    with pytest.raises(EvidenceExists):
        store.put_new(KEY, b"mine")
    assert fake.objects[KEY] == b"raced in between"


def test_s3_retain_identical_retry_and_conflict():
    store = S3EvidenceStore(FakeS3(), "bucket")
    retain(store, RING, KEY, b"one", sha(b"one"))
    retain(store, RING, KEY, b"one", sha(b"one"))
    with pytest.raises(EvidenceConflict):
        retain(store, RING, KEY, b"two", sha(b"two"))


def test_s3_creates_a_missing_bucket_with_versioning():
    fake = FakeS3(bucket_exists=False)
    S3EvidenceStore(fake, "bucket", region="eu-central-1").put_new(KEY, b"x")
    create = next(kw for op, kw in fake.calls if op == "create_bucket")
    assert create["CreateBucketConfiguration"] == {"LocationConstraint": "eu-central-1"}
    assert fake.versioning == {"Status": "Enabled"}


def test_s3_versioning_failure_is_not_fatal():
    fake = FakeS3(bucket_exists=False)

    def refuse(**kw):
        raise _client_error("NotImplemented", 501, "PutBucketVersioning")

    fake.put_bucket_versioning = refuse
    store = S3EvidenceStore(fake, "bucket")
    store.put_new(KEY, b"x")
    assert store.get(KEY) == b"x"


def test_s3_errors_carry_the_code_not_the_request():
    fake = FakeS3()

    def denied(**kw):
        raise _client_error("AccessDenied", 403, "GetObject")

    fake.get_object = denied
    with pytest.raises(EvidenceStoreError) as exc:
        S3EvidenceStore(fake, "bucket").get(KEY)
    assert str(exc.value) == "object store get failed: AccessDenied"

    def unreachable(**kw):
        raise EndpointConnectionError(endpoint_url="http://rustfs:9000")

    fake.head_bucket = unreachable
    with pytest.raises(EvidenceStoreError, match="bucket check failed: EndpointConnectionError"):
        S3EvidenceStore(fake, "bucket").put_new(KEY, b"x")


def test_s3_missing_object():
    with pytest.raises(EvidenceMissing):
        S3EvidenceStore(FakeS3(), "bucket").get(KEY)


# --- selection -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, expected",
    [
        ("", None),
        ("s3://b", ("b", "")),
        ("s3://b/stg/", ("b", "stg")),
        ("s3://b/a/c", ("b", "a/c")),
    ],
)
def test_parse_store_url(url, expected):
    assert parse_store_url(url) == expected


@pytest.mark.parametrize("url", ["s3://", "https://b", "file:///tmp", "s3://b?x=1", "b"])
def test_parse_store_url_refuses_others(url):
    with pytest.raises(ValueError, match="s3://"):
        parse_store_url(url)


def test_store_from_settings(tmp_path):
    local = store_from_settings(Settings(evidence_dir=str(tmp_path)))
    assert isinstance(local, LocalEvidenceStore) and local.root == tmp_path
    s3 = store_from_settings(
        Settings(
            object_store_url="s3://khandaq-evidence/stg",
            object_store_endpoint="http://rustfs.invalid:9000",
            object_store_access_key_id="synthetic-id",
            object_store_secret_access_key="synthetic-secret",
        )
    )
    assert isinstance(s3, S3EvidenceStore)
    assert (s3.bucket, s3.prefix) == ("khandaq-evidence", "stg")
    assert s3.client.meta.endpoint_url == "http://rustfs.invalid:9000"
    with pytest.raises(ValueError):
        store_from_settings(Settings(object_store_url="https://bucket.example"))
