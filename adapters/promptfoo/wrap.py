#!/usr/bin/env python3
"""promptfoo adapter wrapper (spec 010).

Khandaq orchestrates promptfoo (OpenAI, MIT); it does not reimplement it (ADR-0001). promptfoo writes a
single JSON results file; this wrapper's parser turns each failed red-team test into a canonical
finding. The parser is contract-tested against a recorded fixture.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# promptfoo plugin family → (phase, framework ids). ADR-0012.
PLUGIN_FAMILY = {
    "prompt-extraction": ("04-prompt-injection", [("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")]),
    "harmful": ("03-scanning", [("owasp-llm-2026", "LLM07"), ("atlas", "AML.T0048")]),
    "pii": ("03-scanning", [("owasp-llm-2026", "LLM02"), ("atlas", "AML.T0057")]),
}
DEFAULT_FAMILY = ("03-scanning", [("owasp-llm-2026", "LLM07")])


def _results(data: dict) -> list[dict]:
    inner = data.get("results", data)
    if isinstance(inner, dict):
        return inner.get("results", [])
    return inner if isinstance(inner, list) else []


def parse_report(
    report_text: str, *, engagement_id: str, run_id: str, target_ref: str
) -> list[dict]:
    data = json.loads(report_text)
    findings: list[dict] = []
    for res in _results(data):
        # promptfoo red-team: success == False means the model failed the safety test.
        if res.get("success", True):
            continue
        meta = (res.get("testCase") or {}).get("metadata") or {}
        plugin = str(meta.get("pluginId", "unknown"))
        family = plugin.split(":", 1)[0]
        phase, fw = PLUGIN_FAMILY.get(family, DEFAULT_FAMILY)
        severity = str(meta.get("severity", "medium")).lower()
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "medium"
        reason = str((res.get("gradingResult") or {}).get("reason", ""))
        findings.append({
            "schema": "khandaq.finding/1",
            "engagement_id": engagement_id,
            "run_id": run_id,
            "rule_id": f"promptfoo.{plugin}",
            "title": f"promptfoo: {plugin} failed — {reason}"[:200],
            "severity": severity,
            "confidence": "firm",
            "source": {"tool": "promptfoo", "version": "0.118.0", "native_severity": severity},
            "target_ref": target_ref,
            "locations": [{"logicalLocations": [{"fullyQualifiedName": plugin}]}],
            "x-khandaq": {
                "phase": phase,
                "mappings": [{"framework": f, "id": i} for f, i in fw],
                "evidence": [],
            },
        })
    return findings


def main() -> int:  # pragma: no cover - requires a container + promptfoo + a live target
    request = json.loads(Path("/run-request.json").read_text())
    report = Path("/evidence/promptfoo-results.json")
    text = report.read_text() if report.exists() else "{}"
    findings = parse_report(
        text,
        engagement_id=request["engagement_id"],
        run_id=request["run_id"],
        target_ref=request["target"].get("spec", {}).get("host", "target"),
    )
    Path("/evidence/findings.jsonl").write_text("\n".join(json.dumps(f) for f in findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
