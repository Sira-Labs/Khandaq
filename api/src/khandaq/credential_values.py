"""Credential value rules and redaction (spec 028). Pure functions, no database: the Docker runner
uses them on everything an adapter returns, the credential service on what it stores.
"""

from __future__ import annotations

import re

CREDENTIAL_ENV = "KHANDAQ_TARGET_CREDENTIAL"
REDACTION = "[REDACTED:target-credential]"
MIN_VALUE_CHARS, MAX_VALUE_CHARS = 8, 1024
VALUE_RULE = (
    f"a credential is {MIN_VALUE_CHARS} to {MAX_VALUE_CHARS} characters from "
    "A-Z a-z 0-9 . _ ~ + / = : -"
)
# The set that survives a command line, an env file and JSON unchanged; redact() relies on it.
_VALUE = re.compile(rf"[A-Za-z0-9._~+/=:-]{{{MIN_VALUE_CHARS},{MAX_VALUE_CHARS}}}")


class CredentialError(Exception):
    """A credential request cannot be honoured. ``status`` is the HTTP status for the API; the
    message never contains a credential value."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def validate_value(value: object) -> str:
    """The value if it meets the rules; otherwise a 422 that names the rule, never the value."""
    if not isinstance(value, str) or not _VALUE.fullmatch(value):
        raise CredentialError(422, VALUE_RULE)
    return value


def _hex(char: str) -> str:
    """The character's two hex digits, matching either case."""
    return "".join(f"[{d.upper()}{d.lower()}]" if d.isalpha() else d for d in f"{ord(char):02x}")


def _pattern(secret: str) -> str:
    """Matches the secret with each character raw, percent-encoded (``%2B``) or, for the
    punctuation, as a JSON escape (``\\u002b``, ``\\/``), in any mix and in either hex case.

    Every character gets the percent-encoded alternative, the unreserved ones too: several
    encoders write ``~`` as ``%7E``. No alternative is optional or repeated, so the match is linear.
    """
    parts = []
    for char in secret:
        forms = [re.escape(char), "%" + _hex(char)]
        if not char.isalnum():
            forms.append(r"\\u00" + _hex(char))
        if char == "/":
            forms.append(r"\\/")
        parts.append("(?:" + "|".join(forms) + ")")
    return "".join(parts)


def redact(text: str, secret: str | None) -> str:
    """``text`` with every occurrence of ``secret`` replaced by the redaction marker."""
    if not secret:
        return text
    return re.sub(_pattern(secret), REDACTION, text)


def redact_bytes(data: bytes, secret: str | None) -> bytes:
    """As ``redact``, on raw bytes (evidence files are not always text)."""
    if not secret:
        return data
    return re.sub(_pattern(secret).encode("ascii"), REDACTION.encode("ascii"), data)
