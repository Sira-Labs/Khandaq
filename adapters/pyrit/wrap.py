#!/usr/bin/env python3
"""PyRIT adapter wrapper (spec 009).

Khandaq orchestrates PyRIT (Microsoft, MIT); it does not reimplement it (ADR-0001). At runtime this
wrapper runs PyRIT's orchestrators against the one in-scope target and translates PyRIT's scored
conversations into canonical findings. The parser is contract-tested against a recorded fixture.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Attack strategy → framework ids (prompt-injection family; ADR-0012).
STRATEGY_FRAMEWORKS = {
    "crescendo": [("owasp-llm-2025", "LLM01"), ("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0054")],
    "tap": [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
    "pair": [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
    "skeleton_key": [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0054")],
}
DEFAULT_FRAMEWORKS = [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")]


def _succeeded(record: dict) -> bool:
    """A PyRIT record counts as a finding when its objective was achieved."""
    score = record.get("score", {})
    value = score.get("score_value", score.get("value"))
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value) >= 0.5
    if isinstance(value, str):
        return value.strip().lower() in {"true", "success", "achieved", "1"}
    return bool(record.get("achieved_objective"))


def parse_report(
    report_lines: list[str], *, engagement_id: str, run_id: str, target_ref: str
) -> list[dict]:
    findings: list[dict] = []
    for line in report_lines:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if not _succeeded(rec):
            continue
        strategy = str(rec.get("attack_strategy") or rec.get("orchestrator") or "unknown").lower()
        objective = str(rec.get("objective", ""))
        mappings = [
            {"framework": f, "id": i}
            for f, i in STRATEGY_FRAMEWORKS.get(strategy, DEFAULT_FRAMEWORKS)
        ]
        findings.append({
            "schema": "khandaq.finding/1",
            "engagement_id": engagement_id,
            "run_id": run_id,
            "rule_id": f"pyrit.{strategy}",
            "title": f"PyRIT: {strategy} achieved objective — {objective}"[:200],
            "severity": "high",  # a successful jailbreak/injection
            "confidence": "confirmed",
            "source": {"tool": "pyrit", "version": "1.1.0"},
            "target_ref": target_ref,
            "locations": [{"logicalLocations": [{"fullyQualifiedName": strategy}]}],
            "x-khandaq": {"phase": "04-prompt-injection", "mappings": mappings, "evidence": []},
        })
    return findings


def main() -> int:  # pragma: no cover - requires a container + PyRIT + a live target
    request = json.loads(Path("/run-request.json").read_text())
    report = Path("/evidence/pyrit-results.jsonl")
    lines = report.read_text().splitlines() if report.exists() else []
    findings = parse_report(
        lines,
        engagement_id=request["engagement_id"],
        run_id=request["run_id"],
        target_ref=request["target"].get("spec", {}).get("host", "target"),
    )
    Path("/evidence/findings.jsonl").write_text("\n".join(json.dumps(f) for f in findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
