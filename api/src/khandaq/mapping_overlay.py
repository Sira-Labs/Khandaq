"""A deployment's overlay for the framework mapping table (spec 021, ADR-0012).

``KHANDAQ_MAPPINGS_PATH`` names a JSON file in the core's ``khandaq.mappings/1`` schema. The core
combines it with the built-in table: overlay keys replace or add rules and may introduce frameworks,
never change a built-in framework's version or source. A broken overlay stops the app at startup in
every environment. Falling back to the built-in table would quietly drop the deployment's own ids
from every report.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import khandaq_core as kc

MAX_OVERLAY_BYTES = 1 << 20


class MappingOverlayError(RuntimeError):
    """The configured overlay cannot be used; the message says why."""


@dataclass(frozen=True)
class Overlay:
    text: str
    name: str
    sha256: str  # "sha256:<hex>" of the file's exact bytes, named in every report


def load_overlay(path: str) -> Overlay | None:
    """Read and check the overlay at ``path``; ``None`` when no overlay is configured."""
    if not path.strip():
        return None
    file = Path(path)
    try:
        with file.open("rb") as fh:
            data = fh.read(MAX_OVERLAY_BYTES + 1)
    except OSError as exc:
        raise MappingOverlayError(
            f"KHANDAQ_MAPPINGS_PATH {path!r} cannot be read: {exc.strerror}"
        ) from None
    if len(data) > MAX_OVERLAY_BYTES:
        raise MappingOverlayError(
            f"KHANDAQ_MAPPINGS_PATH {path!r} is larger than {MAX_OVERLAY_BYTES} bytes"
        )
    try:
        text = data.decode("utf-8")
        kc.mapping_table(text)  # the core's own check: schema, frameworks, rules
    except (UnicodeDecodeError, ValueError) as exc:
        raise MappingOverlayError(f"KHANDAQ_MAPPINGS_PATH {path!r}: {exc}") from None
    return Overlay(text=text, name=file.name, sha256="sha256:" + hashlib.sha256(data).hexdigest())


@lru_cache(maxsize=4)
def _cached(path: str) -> Overlay | None:
    return load_overlay(path)


def current_overlay() -> Overlay | None:
    """The overlay this process applies, read once and cached; a change takes a restart."""
    from .settings import get_settings

    return _cached(get_settings().mappings_path)
