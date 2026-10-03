"""Envelope encryption for evidence at rest (spec 014, ADR-0016, ADR-0006).

Each object gets a fresh AES-256-GCM data key (DEK). The DEK is wrapped (RFC 3394) under a key
encryption key (KEK) derived with HKDF from ``KHANDAQ_EVIDENCE_KEY``, so any configured key string
of at least 32 characters works and rotation never re-encrypts stored objects. Layout:

    b"KHQE" | 0x01 | kid (8) | wrapped DEK (40) | nonce (12) | AES-GCM ciphertext + tag

The AAD is the 65-byte header plus the object key: a blob moved to another key, or one whose header
was edited, fails to decrypt. The ledger keeps sealing the plaintext's sha256 (ADR-0007), so the
stored form never changes what is sealed.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

if TYPE_CHECKING:
    from .settings import Settings

MAGIC = b"KHQE"
VERSION = 1
MIN_KEY_CHARS = 32
_KID_LEN, _WRAPPED_LEN, _NONCE_LEN = 8, 40, 12
HEADER_LEN = len(MAGIC) + 1 + _KID_LEN + _WRAPPED_LEN + _NONCE_LEN  # 65
_AAD_DOMAIN = b"khandaq.evidence/1\x00"


class EvidenceKeyError(ValueError):
    """No usable evidence key is configured (missing or too short)."""


class EvidenceDecryptError(ValueError):
    """A stored blob cannot be decrypted: unknown key id, edited header or ciphertext, wrong key."""


def is_envelope(blob: bytes) -> bool:
    """True if ``blob`` carries an ADR-0016 header (objects stored before spec 014 do not)."""
    return blob[: len(MAGIC) + 1] == MAGIC + bytes([VERSION])


def _derive_kek(secret: str) -> bytes:
    if len(secret) < MIN_KEY_CHARS:
        raise EvidenceKeyError(f"evidence keys must be at least {MIN_KEY_CHARS} characters")
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"khandaq", info=b"khandaq.evidence-kek/1"
    ).derive(secret.encode("utf-8"))


def _kid(kek: bytes) -> bytes:
    return hashlib.sha256(kek).digest()[:_KID_LEN]


@dataclass(frozen=True)
class Keyring:
    """The current KEK (encrypts and decrypts) and retired KEKs (decrypt only), by key id."""

    current_kid: bytes
    keks: dict[bytes, bytes]

    @classmethod
    def from_secrets(cls, current: str, previous: list[str] | None = None) -> Keyring:
        if not current:
            raise EvidenceKeyError("KHANDAQ_EVIDENCE_KEY is not set; evidence cannot be stored")
        kek = _derive_kek(current)
        keks = {_kid(kek): kek}
        for secret in previous or []:
            old = _derive_kek(secret)
            keks.setdefault(_kid(old), old)
        return cls(current_kid=_kid(kek), keks=keks)

    @classmethod
    def from_settings(cls, settings: Settings) -> Keyring:
        previous = [k.strip() for k in settings.evidence_previous_keys.split(",") if k.strip()]
        return cls.from_secrets(settings.evidence_key, previous)

    def encrypt(self, object_key: str, plaintext: bytes) -> bytes:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_LEN)
        wrapped = aes_key_wrap(self.keks[self.current_kid], dek)
        header = MAGIC + bytes([VERSION]) + self.current_kid + wrapped + nonce
        return header + AESGCM(dek).encrypt(nonce, plaintext, _aad(header, object_key))

    def decrypt(self, object_key: str, blob: bytes) -> bytes:
        if len(blob) < HEADER_LEN + 16 or not is_envelope(blob):
            raise EvidenceDecryptError("not an evidence envelope")
        header = blob[:HEADER_LEN]
        offset = len(MAGIC) + 1
        kid = header[offset : offset + _KID_LEN]
        wrapped = header[offset + _KID_LEN : offset + _KID_LEN + _WRAPPED_LEN]
        nonce = header[HEADER_LEN - _NONCE_LEN :]
        kek = self.keks.get(kid)
        if kek is None:
            raise EvidenceDecryptError(f"encrypted under unknown key id {kid.hex()}")
        try:
            dek = aes_key_unwrap(kek, wrapped)
            return AESGCM(dek).decrypt(nonce, blob[HEADER_LEN:], _aad(header, object_key))
        except (InvalidUnwrap, InvalidTag) as exc:
            raise EvidenceDecryptError("evidence envelope failed authentication") from exc


def _aad(header: bytes, object_key: str) -> bytes:
    return _AAD_DOMAIN + header + object_key.encode("utf-8")
