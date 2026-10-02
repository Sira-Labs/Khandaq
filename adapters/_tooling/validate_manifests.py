#!/usr/bin/env python3
"""Validate every adapters/<tool>/adapter.yaml (spec 005, runs in CI).

An adapter must pin an EXACT upstream version (never a floating tag like "latest"), cover at least one
phase, and ship a native->canonical severity table (ADR-0001/0004). A non-builtin adapter must name a
container image. Exits non-zero if any manifest is invalid.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def validate_manifest(data: dict) -> list[str]:
    problems: list[str] = []
    name = data.get("name")
    version = data.get("version")
    if not name:
        problems.append("name is required")
    if not version:
        problems.append("version (exact upstream) is required")
    elif str(version).lower() in {"latest", "main", "master", "edge"}:
        problems.append(f"version must be exact, not a floating tag '{version}'")
    if not data.get("phases"):
        problems.append("at least one phase is required")
    table = data.get("severity_table") or {}
    if not table:
        problems.append("a severity_table (native->canonical) is required")
    else:
        bad = sorted(set(table.values()) - VALID_SEVERITIES)
        if bad:
            problems.append(f"severity_table maps to unknown severities: {bad}")
    if not data.get("builtin") and not data.get("image"):
        problems.append("a container image is required (or set builtin: true)")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    manifests = sorted((root / "adapters").glob("*/adapter.yaml"))
    if not manifests:
        print("no adapter manifests found (nothing to validate)")
        return 0
    ok = True
    for path in manifests:
        data = yaml.safe_load(path.read_text()) or {}
        problems = validate_manifest(data)
        rel = path.relative_to(root)
        if problems:
            ok = False
            print(f"✗ {rel}")
            for p in problems:
                print(f"    - {p}")
        else:
            print(f"✓ {rel} ({data['name']} {data['version']})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
