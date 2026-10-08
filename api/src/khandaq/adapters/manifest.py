"""Adapter manifest model (spec 005).

An adapter is the only sanctioned way to add a tool (ADR-0001): a thin wrapper, an exact pinned
upstream version, and a documented native→canonical severity table. The manifest describes it. The
on-disk `adapter.yaml` files under `adapters/` are validated in CI by
`adapters/_tooling/validate_manifests.py`; this dataclass is the in-process representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AdapterManifest:
    name: str
    version: str  # exact upstream version (ADR-0001)
    phases: list[str]
    frameworks: list[str] = field(default_factory=list)
    severity_table: dict[str, str] = field(default_factory=dict)
    image: str | None = None
    entrypoint: str | None = None
    resources: dict = field(default_factory=dict)
    builtin: bool = False  # True for in-process adapters (e.g. echo) that need no container
    # True when the adapter holds a requests-per-minute limit itself (spec 027). One that cannot is
    # refused when the rules of engagement cap the rate, rather than risk exceeding it.
    paces_requests: bool = False

    def problems(self) -> list[str]:
        """Return reasons this manifest is invalid (empty list = valid)."""
        issues = []
        if not self.name:
            issues.append("name is required")
        if not self.version:
            issues.append("version (exact upstream) is required")
        if not self.phases:
            issues.append("at least one phase is required")
        if not self.severity_table:
            issues.append("a severity_table (native→canonical) is required")
        else:
            valid = {"info", "low", "medium", "high", "critical"}
            bad = sorted(set(self.severity_table.values()) - valid)
            if bad:
                issues.append(f"severity_table maps to unknown severities: {bad}")
        if not self.builtin and not self.image:
            issues.append("a container image is required (or mark the adapter builtin)")
        return issues
