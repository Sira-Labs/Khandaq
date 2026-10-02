"""Adapter registry (spec 005).

For R1 the registry holds the built-in in-process ``echo`` adapter used for the demo and tests. Real
tool adapters (garak, PyRIT, …) are loaded from their on-disk ``adapters/<tool>/adapter.yaml``
manifests as they land (spec 006+); that loader is added with the first real adapter.
"""

from __future__ import annotations

from .manifest import AdapterManifest

ECHO = AdapterManifest(
    name="echo",
    version="0.1.0",
    phases=["04-prompt-injection"],
    frameworks=["owasp-llm-2026", "atlas"],
    severity_table={
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    },
    builtin=True,
)

_BUILTIN = {ECHO.name: ECHO}


def get_manifest(name: str) -> AdapterManifest | None:
    return _BUILTIN.get(name)


def known_adapters() -> list[str]:
    return sorted(_BUILTIN)
