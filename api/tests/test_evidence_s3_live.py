"""The S3 evidence store against a real S3-compatible server (spec 014 part 2).

CI runs RustFS 1.0.0, the version the deployments pin, as a service; locally set
``KHANDAQ_TEST_S3_ENDPOINT`` (and the two credential variables) to run it. Synthetic data only.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid

import pytest

from khandaq.evidence_crypto import Keyring
from khandaq.evidence_store import (
    EvidenceConflict,
    EvidenceMissing,
    S3EvidenceStore,
    read_verified,
    retain,
    store_from_settings,
)
from khandaq.settings import Settings

ENDPOINT = os.environ.get("KHANDAQ_TEST_S3_ENDPOINT")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="KHANDAQ_TEST_S3_ENDPOINT not set")

RING = Keyring.from_secrets("synthetic-evidence-key-for-tests-0001")


@pytest.fixture(scope="module")
def store() -> S3EvidenceStore:
    from botocore.exceptions import BotoCoreError, ClientError

    settings = Settings(
        object_store_url=f"s3://khq-test-{uuid.uuid4().hex[:12]}/stg",
        object_store_endpoint=ENDPOINT,
        object_store_access_key_id=os.environ.get("KHANDAQ_TEST_S3_ACCESS_KEY_ID", ""),
        object_store_secret_access_key=os.environ.get("KHANDAQ_TEST_S3_SECRET_ACCESS_KEY", ""),
    )
    s3 = store_from_settings(settings)
    assert isinstance(s3, S3EvidenceStore)
    deadline = time.monotonic() + 30  # the service container may still be starting
    while True:
        try:
            s3.client.list_buckets()
            return s3
        except (BotoCoreError, ClientError):
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_live_store_round_trip_bucket_and_versioning(store):
    data = b'{"probe": "synthetic"}\n'
    retain(store, RING, "eng/run/report.jsonl", data, _sha(data))  # creates the bucket
    raw = store.client.get_object(Bucket=store.bucket, Key="stg/eng/run/report.jsonl")
    assert raw["Body"].read().startswith(b"KHQE")
    assert read_verified(store, RING, "eng/run/report.jsonl", _sha(data)) == data
    versioning = store.client.get_bucket_versioning(Bucket=store.bucket)
    assert versioning.get("Status") == "Enabled"


def test_live_store_is_write_once(store):
    data = b"first"
    retain(store, RING, "eng/run/once.txt", data, _sha(data))
    retain(store, RING, "eng/run/once.txt", data, _sha(data))  # identical retry
    with pytest.raises(EvidenceConflict):
        retain(store, RING, "eng/run/once.txt", b"second", _sha(b"second"))
    # The server itself refuses a conditional overwrite, even past the HEAD check.
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError) as exc:
        store.client.put_object(
            Bucket=store.bucket, Key="stg/eng/run/once.txt", Body=b"x", IfNoneMatch="*"
        )
    assert exc.value.response["Error"]["Code"] in {"PreconditionFailed", "412"}
    assert read_verified(store, RING, "eng/run/once.txt", _sha(data)) == data


def test_live_store_missing_object(store):
    with pytest.raises(EvidenceMissing):
        store.get("eng/run/never-written")
