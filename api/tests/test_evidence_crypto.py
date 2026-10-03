"""Evidence envelope encryption (spec 014, ADR-0016). Synthetic keys only."""

from __future__ import annotations

import pytest

from khandaq.evidence_crypto import (
    HEADER_LEN,
    EvidenceDecryptError,
    EvidenceKeyError,
    Keyring,
    is_envelope,
)

KEY = "synthetic-evidence-key-for-tests-0001"
OLD_KEY = "synthetic-evidence-key-for-tests-old-1"
OBJECT = "eng_1/run_1/garak.report.jsonl"


def test_round_trip_and_layout():
    ring = Keyring.from_secrets(KEY)
    blob = ring.encrypt(OBJECT, b"tool output")
    assert is_envelope(blob) and blob[:4] == b"KHQE"
    assert len(blob) == HEADER_LEN + len(b"tool output") + 16  # GCM tag
    assert b"tool output" not in blob
    assert ring.decrypt(OBJECT, blob) == b"tool output"
    # Fresh DEK and nonce per object: the same plaintext never encrypts the same way twice.
    assert ring.encrypt(OBJECT, b"tool output") != blob


def test_any_long_enough_key_shape_works():
    for secret in (
        "a" * 32,
        "0123456789abcdef0123456789abcdef",
        "c3ludGhldGljLWtleS1iYXNlNjQtMzItYnl0ZXM=",
    ):
        ring = Keyring.from_secrets(secret)
        assert ring.decrypt(OBJECT, ring.encrypt(OBJECT, b"x")) == b"x"


def test_blob_is_bound_to_its_object_key():
    ring = Keyring.from_secrets(KEY)
    blob = ring.encrypt(OBJECT, b"tool output")
    with pytest.raises(EvidenceDecryptError):
        ring.decrypt("eng_1/run_2/garak.report.jsonl", blob)


@pytest.mark.parametrize("offset", [5, 13, HEADER_LEN - 1, HEADER_LEN, -1])
def test_any_flipped_byte_fails(offset):
    ring = Keyring.from_secrets(KEY)
    blob = bytearray(ring.encrypt(OBJECT, b"tool output"))
    blob[offset] ^= 0x01
    with pytest.raises(EvidenceDecryptError):
        ring.decrypt(OBJECT, bytes(blob))


def test_unknown_key_id_and_wrong_key_fail():
    blob = Keyring.from_secrets(KEY).encrypt(OBJECT, b"tool output")
    with pytest.raises(EvidenceDecryptError, match="unknown key id"):
        Keyring.from_secrets(OLD_KEY).decrypt(OBJECT, blob)


def test_not_an_envelope():
    with pytest.raises(EvidenceDecryptError, match="not an evidence envelope"):
        Keyring.from_secrets(KEY).decrypt(OBJECT, b'{"probe": "plaintext"}')


def test_rotation_keeps_old_objects_readable():
    old_blob = Keyring.from_secrets(OLD_KEY).encrypt(OBJECT, b"old")
    rotated = Keyring.from_secrets(KEY, [OLD_KEY])
    assert rotated.decrypt(OBJECT, old_blob) == b"old"
    new_blob = rotated.encrypt(OBJECT, b"new")
    # New writes use the current key: a keyring without the old key reads them.
    assert Keyring.from_secrets(KEY).decrypt(OBJECT, new_blob) == b"new"
    with pytest.raises(EvidenceDecryptError):
        Keyring.from_secrets(OLD_KEY).decrypt(OBJECT, new_blob)


@pytest.mark.parametrize("current, previous", [("", []), ("short", []), (KEY, ["short"])])
def test_missing_or_short_keys_are_refused(current, previous):
    with pytest.raises(EvidenceKeyError):
        Keyring.from_secrets(current, previous)
