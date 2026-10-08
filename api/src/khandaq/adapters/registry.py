"""Adapter registry (specs 005 and 027).

The built-in in-process ``echo`` adapter (demo and tests) and the container adapters whose wrapper
runs its tool in the sandbox. Each container manifest mirrors ``adapters/<tool>/adapter.yaml``; a
drift test keeps the two equal. An adapter is listed here only once its image really runs the tool,
so a run can never be queued for a wrapper that would only parse a report it was handed.
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
    paces_requests=True,  # it sends nothing to the target, so no rate limit can be exceeded
)

# garak runs one request at a time but has no requests-per-minute limiter (spec 027).
GARAK = AdapterManifest(
    name="garak",
    version="0.17.0",
    phases=["03-scanning", "04-prompt-injection"],
    frameworks=["owasp-llm-2025", "owasp-llm-2026", "atlas"],
    severity_table={"high": "high", "medium": "medium", "low": "low"},
    image="ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0",
    entrypoint="/usr/local/bin/wrap.py",
    resources={"cpu": "1", "memory": "2Gi"},
)

_REGISTRY = {m.name: m for m in (ECHO, GARAK)}


def get_manifest(name: str) -> AdapterManifest | None:
    return _REGISTRY.get(name)


def known_adapters() -> list[str]:
    return sorted(_REGISTRY)


def all_manifests() -> list[AdapterManifest]:
    """Every registered adapter, by name."""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]
