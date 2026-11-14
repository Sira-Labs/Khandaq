#!/usr/bin/env python3
"""Cisco mcp-scanner adapter wrapper (specs 025 and 031).

Khandaq orchestrates mcp-scanner (Cisco, Apache-2.0); it does not reimplement it (ADR-0001). Inside
the run sandbox (spec 012) this wrapper reads the scope-checked run request, runs the pinned
scanner's own ``remote`` scan with its bundled YARA rules against the one in-scope MCP server, and
turns each threat an analyzer reported on a tool into a canonical finding. It adds no rules or
detection logic of its own. The parser is contract-tested against a recorded fixture.

Only the server the control plane passed is ever used; the sandbox's network reaches no other host.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import IO
from urllib.parse import urlsplit

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
            if item.get("status") in NOT_SCANNED:
                continue  # validated above, but a failed or skipped item reports nothing
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


# --- running mcp-scanner (spec 031) ---------------------------------------------------------------

SCANNER = "mcp-scanner"
# The only analyzer that works on what the scan itself fetched. The others send the server's tool
# descriptions to a third party (Cisco AI Defense, an LLM, VirusTotal): the sandbox has no route
# there, and an engagement has not authorised it.
ANALYZER = "yara"
FINDINGS_NAME = "findings.jsonl"
CREDENTIAL_ENV = "KHANDAQ_TARGET_CREDENTIAL"
# Settings of the scanner that could switch on another analyzer or point it elsewhere.
_SCANNER_SETTINGS = ("MCP_SCANNER_", "VIRUSTOTAL_")


class RequestError(ValueError):
    """The run request cannot be turned into a scan; the run fails before the scanner starts."""


def load_request(environ: dict[str, str], fallback: Path) -> dict:
    """The run request from ``KHANDAQ_RUN_REQUEST`` (the sandbox contract), else from a file."""
    raw = environ.get("KHANDAQ_RUN_REQUEST")
    if raw is None:
        if not fallback.is_file():
            raise RequestError("no run request: KHANDAQ_RUN_REQUEST is not set")
        raw = fallback.read_text()
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RequestError(f"the run request is not JSON: {exc}") from exc
    if not isinstance(request, dict) or not isinstance(request.get("target"), dict):
        raise RequestError("the run request has no target")
    return request


def server_url(target: dict) -> str:
    """The MCP server's URL, unchanged: the request the scanner makes is the URL the scope lock
    authorised (an ``mcp_server`` target is matched by its exact URL)."""
    if target.get("type") != "mcp_server":
        raise RequestError(f"mcp-scanner scans an MCP server, not a {target.get('type')!r}")
    url = (target.get("spec") or {}).get("url")
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        raise RequestError("the target needs an absolute http(s) URL")
    if parts.fragment:
        raise RequestError("the target URL must not carry a fragment")
    return url


def check_analyzers(params: dict) -> None:
    """Only the YARA analyzer runs; a request for any other fails the run instead of being dropped."""
    wanted = params.get("analyzers")
    if wanted is None:
        return
    if isinstance(wanted, str):
        wanted = [a.strip() for a in wanted.split(",") if a.strip()]
    if wanted != [ANALYZER]:
        raise RequestError(f"only the {ANALYZER!r} analyzer runs in the sandbox, got {wanted!r}")


def scanner_command(url: str, credential: str | None = None) -> list[str]:
    """The mcp-scanner CLI invocation: its own ``remote`` scan, YARA only, raw report on stdout.

    A target credential (spec 028) is the scanner's ``--bearer-token``, the tool's only interface
    for one: an argument of a process inside this run's container, never of ``docker``.
    """
    command = [SCANNER, "--analyzers", ANALYZER, "--format", "raw", "remote", "--server-url", url]
    if credential:
        command += ["--bearer-token", credential]
    return command


def scanner_env(environ: dict[str, str]) -> dict[str, str]:
    """The scanner's environment: without the run request, the credential variable, or any setting
    that could enable another analyzer."""
    return {
        k: v
        for k, v in environ.items()
        if k not in ("KHANDAQ_RUN_REQUEST", CREDENTIAL_ENV) and not k.startswith(_SCANNER_SETTINGS)
    }


def write_tar(evidence: Path, out: IO[bytes]) -> None:
    """The sandbox output contract (spec 012): one uncompressed tar of ``evidence`` on stdout."""
    with tarfile.open(fileobj=out, mode="w|") as tar:
        for path in sorted(evidence.iterdir()):
            tar.add(path, arcname=path.name)


def run(request: dict, *, evidence: Path, environ: dict[str, str], runner=None) -> int:
    """Scan the request's MCP server and write the raw report and ``findings.jsonl`` into
    ``evidence``.

    Returns non-zero, with no findings file, on any failure: a scan that produced no trustworthy
    report must surface as a failed run, never as a run with zero findings.
    """
    try:
        url = server_url(request["target"])
        check_analyzers(request.get("params") or {})
    except RequestError as exc:
        print(f"mcp-scanner adapter: {exc}", file=sys.stderr)
        return 2
    command = scanner_command(url, environ.get(CREDENTIAL_ENV) or None)
    print(f"mcp-scanner adapter: scanning with mcp-scanner {VERSION} ({ANALYZER})", file=sys.stderr)
    # The raw report is the scanner's stdout; its console output goes to stderr, because this
    # process's stdout carries only the evidence tar.
    result = (runner or subprocess.run)(
        command,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        env=scanner_env(environ),
        check=False,
    )
    report = result.stdout or b""
    if result.returncode != 0 or not report.strip():
        print(
            f"mcp-scanner adapter: the scanner exited with {result.returncode} and "
            f"{len(report)} bytes of report",
            file=sys.stderr,
        )
        return 2
    try:
        findings = parse_report(
            report.decode("utf-8"),
            engagement_id=request["engagement_id"],
            run_id=request["run_id"],
            target_ref=_target_ref(request["target"]),
        )
        missed = unscanned_items(report.decode("utf-8"))
    except (ReportError, UnicodeDecodeError) as exc:
        print(f"mcp-scanner adapter: refusing an untrustworthy report: {exc}", file=sys.stderr)
        return 2
    if missed:
        # A partial scan is a failed run: its findings would read as the whole picture, and a
        # report with nothing flagged would read as clean although an item was never checked.
        print(
            f"mcp-scanner adapter: {len(missed)} item(s) were not scanned: {', '.join(missed[:10])}",
            file=sys.stderr,
        )
        return 2
    (evidence / REPORT_NAME).write_bytes(report)
    for finding in findings:
        finding["_evidence_local"] = [REPORT_NAME]
    (evidence / FINDINGS_NAME).write_text("".join(json.dumps(f) + "\n" for f in findings))
    return 0


def unscanned_items(report_text: str) -> list[str]:
    """The items of a report the parser accepted that no analyzer actually covered: failed or
    skipped by the tool, or with every analyzer entry errored. The parser keeps them out of the
    findings (spec 025); a run must not pass them off as clean (spec 031)."""
    missed = []
    for index, item in enumerate(json.loads(report_text)["scan_results"]):
        entries = item["findings"]
        errored = sum(1 for entry in entries.values() if entry.get("status") == "error")
        if item.get("status") in NOT_SCANNED or errored >= len(entries):
            item_type, name = _item_label(item, index)
            missed.append(f"{item_type} {name!r}")
    return missed


def _target_ref(target: dict) -> str:
    spec = target.get("spec") or {}
    return str(spec.get("url") or spec.get("host") or "target")


def main(
    request_path: Path = Path("/run-request.json"),
    evidence: Path = Path("/evidence"),
    out: IO[bytes] | None = None,
) -> int:
    """Sandbox entrypoint: run the scan, then emit the evidence tar on stdout (only on success)."""
    environ = dict(os.environ)
    try:
        request = load_request(environ, request_path)
    except RequestError as exc:
        print(f"mcp-scanner adapter: {exc}", file=sys.stderr)
        return 2
    code = run(request, evidence=evidence, environ=environ)
    if code == 0:
        write_tar(evidence, out or sys.stdout.buffer)
    return code


if __name__ == "__main__":
    sys.exit(main())
