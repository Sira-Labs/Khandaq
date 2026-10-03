#!/usr/bin/env python3
"""Cisco mcp-scanner adapter wrapper (spec 025).

Khandaq orchestrates mcp-scanner (Cisco, Apache-2.0); it does not reimplement it (ADR-0001).
``mcp-scanner --format raw`` writes one JSON report per MCP server; this wrapper's parser turns
each threat an analyzer reported on a tool, prompt or resource into a canonical finding. The parser
is contract-tested against a recorded fixture.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

VERSION = "4.8.5"
PHASE = "07-agentic-mcp"
REPORT_NAME = "mcp-scanner-results.json"

# Threat family (the slug of mcp-scanner's threat name) → framework ids. ADR-0012, spec 025. Only
# families with an unambiguous id are curated; any other threat is left to the core table, which
# has no mcp-scanner default (an uncurated threat is `unmapped`, as for garak).
THREAT_FRAMEWORKS = {
    "prompt-injection": [
        ("owasp-llm-2025", "LLM01"),
        ("owasp-llm-2026", "LLM01"),
        ("atlas", "AML.T0051"),
    ],
    "tool-poisoning": [("owasp-agentic", "ASI04"), ("atlas", "AML.T0053")],
    "data-exfiltration": [
        ("owasp-llm-2025", "LLM02"),
        ("owasp-llm-2026", "LLM02"),
        ("atlas", "AML.T0057"),
    ],
    "code-execution": [("owasp-agentic", "ASI05")],
}

# The raw format keeps one severity per analyzer per item and only ever promotes it to HIGH,
# MEDIUM or LOW; INFO (or unrated) findings are counted but leave the entry at SAFE.
SEVERITIES = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
LEVELS = {*SEVERITIES, "SAFE", "UNKNOWN"}
NOT_SCANNED = {"failed", "skipped"}

# The name field of each item type the tool reports.
ITEM_NAMES = {"tool": "tool_name", "prompt": "prompt_name", "resource": "resource_uri"}


class ReportError(ValueError):
    """The mcp-scanner report cannot be trusted as a complete account of the scan. The wrapper exits
    non-zero rather than emit a partial or empty finding set that would read as "clean"."""


def threat_slug(name: str) -> str:
    """``TOOL POISONING`` and ``PROMPT_INJECTION`` → ``tool-poisoning``, ``prompt-injection``."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "unknown"


def _count(entry: dict, where: str) -> int:
    count = entry.get("total_findings")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ReportError(f"{where}: total_findings is not a non-negative integer: {count!r}")
    return count


def _item_label(item: dict, index: int) -> tuple[str, str]:
    item_type = str(item.get("item_type") or "tool")
    name = item.get(ITEM_NAMES.get(item_type, "tool_name")) or item.get("resource_name")
    return item_type, str(name or f"item-{index}")


def parse_report(
    report_text: str, *, engagement_id: str, run_id: str, target_ref: str
) -> list[dict]:
    """Translate an mcp-scanner raw report into canonical findings (item × analyzer × threat).

    Fails closed (ReportError) on a report that is empty, not JSON, has no scan results, carries an
    unknown severity or count, contradicts itself, or in which nothing was actually scanned.
    """
    if not report_text.strip():
        raise ReportError("the report is empty")
    try:
        data = json.loads(report_text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"the report is not valid JSON (truncated?): {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("scan_results"), list):
        raise ReportError("the report has no list of scan results")
    items = data["scan_results"]
    if not items:
        raise ReportError("the report has no scan results: nothing was scanned")

    findings: list[dict] = []
    scanned = 0
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("findings"), dict):
            raise ReportError(f"scan result {index} is not an object with a findings object")
        item_type, name = _item_label(item, index)
        entries = item["findings"]
        errored = 0
        for analyzer, entry in entries.items():
            where = f"{item_type} {name!r}, {analyzer}"
            if not isinstance(entry, dict):
                raise ReportError(f"{where}: the analyzer entry is not an object")
            level = entry.get("severity")
            if level not in LEVELS:
                raise ReportError(f"{where}: unknown severity {level!r}")
            count = _count(entry, where)
            if entry.get("status") == "error":
                errored += 1
                continue
            if count == 0:
                if level in SEVERITIES:
                    raise ReportError(f"{where}: severity {level} with no findings counted")
                continue
            threats = entry.get("threat_names")
            if not isinstance(threats, list) or not threats:
                raise ReportError(f"{where}: {count} findings counted but no threat names")
            severity = SEVERITIES.get(level, "info")
            summary = str(entry.get("threat_summary") or "")
            location = {"logicalLocations": [{"fullyQualifiedName": f"{item_type}:{name}"}]}
            for threat in dict.fromkeys(str(t) for t in threats):  # dedupe, keep order
                slug = threat_slug(threat)
                mappings = [{"framework": f, "id": i} for f, i in THREAT_FRAMEWORKS.get(slug, [])]
                findings.append({
                    "schema": "khandaq.finding/2",
                    "engagement_id": engagement_id,
                    "run_id": run_id,
                    "rule_id": f"mcp-scanner.{slug}",
                    "title": f"mcp-scanner: {threat} in {item_type} {name} — {summary}"[:200],
                    "severity": severity,
                    "confidence": "firm",
                    "source": {"tool": "mcp-scanner", "version": VERSION, "native_severity": level},
                    "target_ref": target_ref,
                    "locations": [location],
                    "x-khandaq": {
                        "phase": PHASE,
                        "mappings": mappings,
                        "evidence": [],
                    },
                })  # fmt: skip
        # Scanned = not failed or skipped, and at least one analyzer finished on it.
        if item.get("status") not in NOT_SCANNED and errored < len(entries):
            scanned += 1
    if scanned == 0:
        raise ReportError(f"none of the {len(items)} items was actually scanned")
    return findings


def _target_ref(target: dict) -> str:
    spec = target.get("spec") or {}
    return str(spec.get("url") or spec.get("host") or "target")


def main(request_path: Path = Path("/run-request.json"), evidence: Path = Path("/evidence")) -> int:
    """Translate the mcp-scanner report in ``evidence`` into ``findings.jsonl``.

    Exits non-zero, and writes no findings file, when the report is missing, incomplete or
    unreadable: a scan that produced no trustworthy report must surface as a failed run, never as a
    run with zero findings. Invoking mcp-scanner itself inside the run sandbox lands with the other
    adapters (spec 012); until then the report must already be present.
    """
    request = json.loads(request_path.read_text())
    report = evidence / REPORT_NAME
    if not report.is_file():
        print(f"mcp-scanner adapter: {report} is missing; mcp-scanner did not run", file=sys.stderr)
        return 2
    try:
        findings = parse_report(
            report.read_text(),
            engagement_id=request["engagement_id"],
            run_id=request["run_id"],
            target_ref=_target_ref(request.get("target") or {}),
        )
    except ReportError as exc:
        print(f"mcp-scanner adapter: refusing untrustworthy report: {exc}", file=sys.stderr)
        return 2
    (evidence / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
