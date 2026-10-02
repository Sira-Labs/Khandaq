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

# promptfoo plugin family → (phase, framework ids). ADR-0012. OWASP LLM 2025 ids are listed only
# where the 2025 category is unambiguous (LLM02 sensitive information disclosure, LLM07 system
# prompt leakage); 2025 has no category for harmful content as such.
PLUGIN_FAMILY = {
    "prompt-extraction": (
        "04-prompt-injection",
        [("owasp-llm-2025", "LLM07"), ("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
    ),
    "harmful": ("03-scanning", [("owasp-llm-2026", "LLM07"), ("atlas", "AML.T0048")]),
    "pii": (
        "03-scanning",
        [("owasp-llm-2025", "LLM02"), ("owasp-llm-2026", "LLM02"), ("atlas", "AML.T0057")],
    ),
}
DEFAULT_FAMILY = ("03-scanning", [("owasp-llm-2026", "LLM07")])
SEVERITIES = {"info", "low", "medium", "high", "critical"}

REPORT_NAME = "promptfoo-results.json"
# promptfoo's ResultFailureReason: 0 none, 1 an assertion failed, 2 the test errored.
FAILURE_ASSERT = 1
FAILURE_ERROR = 2


class ReportError(ValueError):
    """The promptfoo output cannot be trusted as a complete account of the run. The wrapper exits
    non-zero rather than emit a partial or empty finding set that would read as "clean"."""


def _results(data: object) -> tuple[list[dict], dict | None]:
    """The ``EvaluateResult`` list and ``EvaluateStats`` of a promptfoo output file
    (``{"results": {"results": [...], "stats": {...}}}``); a bare summary or list is accepted."""
    inner = data.get("results", data) if isinstance(data, dict) else data
    stats = None
    if isinstance(inner, dict):
        stats = inner.get("stats") if isinstance(inner.get("stats"), dict) else None
        inner = inner.get("results")
    if not isinstance(inner, list) or not all(isinstance(r, dict) for r in inner):
        raise ReportError("the output has no list of results")
    return inner, stats


def _failure_reason(res: dict) -> int:
    if not isinstance(res.get("success"), bool):
        raise ReportError(f"a result has no boolean 'success': {str(res)[:120]}")
    reason = res.get("failureReason")
    if reason is not None:
        if isinstance(reason, bool) or reason not in (0, FAILURE_ASSERT, FAILURE_ERROR):
            raise ReportError(f"a result has an unknown failureReason {reason!r}")
        if (reason == 0) != res["success"]:
            # A failed test with no reason, or a passed one with one, would silently vanish.
            raise ReportError(f"a result's success disagrees with failureReason {reason}")
        return int(reason)
    # Older outputs carry no failureReason: an error message marks an errored test.
    if res.get("error"):
        return FAILURE_ERROR
    return 0 if res["success"] else FAILURE_ASSERT


def parse_report(
    report_text: str, *, engagement_id: str, run_id: str, target_ref: str
) -> list[dict]:
    """Translate a promptfoo output file into canonical findings, one per failed red-team test.

    A test that **errored** (``failureReason`` 2: the provider failed, timed out or refused the
    request) is not a vulnerability and is not a finding; only a failed assertion is. Fails closed:
    output that is not JSON, has no result list, disagrees with its own stats, has no results, or
    in which every test errored raises ReportError.
    """
    if not report_text.strip():
        raise ReportError("the output file is empty")
    try:
        data = json.loads(report_text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"the output is not valid JSON (truncated?): {exc}") from exc
    results, stats = _results(data)
    if not results:
        raise ReportError("the output has no results: no test was run")
    if stats is not None:
        counted = sum(
            v for k in ("successes", "failures", "errors")
            if isinstance(v := stats.get(k), int) and not isinstance(v, bool)
        )  # fmt: skip
        if counted != len(results):
            raise ReportError(f"the stats count {counted} tests, the output has {len(results)}")
    errored = 0
    findings: list[dict] = []
    for res in results:
        reason = _failure_reason(res)
        if reason == FAILURE_ERROR:
            errored += 1
            continue
        if res.get("success") is True or reason != FAILURE_ASSERT:
            continue
        meta = (res.get("testCase") or {}).get("metadata") or res.get("metadata") or {}
        plugin = str(meta.get("pluginId") or "unknown")
        family = plugin.split(":", 1)[0]
        phase, fw = PLUGIN_FAMILY.get(family, DEFAULT_FAMILY)
        severity = str(meta.get("severity") or "medium").lower()
        if severity not in SEVERITIES:
            severity = "medium"
        reason_text = str((res.get("gradingResult") or {}).get("reason") or "")
        findings.append({
            "schema": "khandaq.finding/1",
            "engagement_id": engagement_id,
            "run_id": run_id,
            "rule_id": f"promptfoo.{plugin}",
            "title": f"promptfoo: {plugin} failed — {reason_text}"[:200],
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
        })  # fmt: skip
    if errored == len(results):
        raise ReportError(f"all {errored} tests errored: the target was never actually tested")
    return findings


def main(request_path: Path = Path("/run-request.json"), evidence: Path = Path("/evidence")) -> int:
    """Translate the promptfoo output in ``evidence`` into ``findings.jsonl``.

    Exits non-zero, and writes no findings file, when the output is missing, incomplete or
    unreadable: a run that produced no trustworthy output must surface as a failed run, never as a
    run with zero findings. Invoking promptfoo itself inside the run sandbox lands with Docker
    execution on the worker (spec 010 notes); until then the output must already be present.
    """
    request = json.loads(request_path.read_text())
    report = evidence / REPORT_NAME
    if not report.is_file():
        print(f"promptfoo adapter: {report} is missing; promptfoo did not run", file=sys.stderr)
        return 2
    try:
        findings = parse_report(
            report.read_text(),
            engagement_id=request["engagement_id"],
            run_id=request["run_id"],
            target_ref=request["target"].get("spec", {}).get("host", "target"),
        )
    except ReportError as exc:
        print(f"promptfoo adapter: refusing untrustworthy output: {exc}", file=sys.stderr)
        return 2
    (evidence / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
