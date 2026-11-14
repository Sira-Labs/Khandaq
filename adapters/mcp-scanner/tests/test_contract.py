"""Contract test for the Cisco mcp-scanner adapter (spec 025)."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import jsonschema
import pytest

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent
REPO = HERE.parents[2]
SCHEMA = json.loads((REPO / "core/khandaq-core/schema/finding.schema.json").read_text())
FIXTURE = json.loads((ADAPTER / "fixtures/mcp-scanner-results.json").read_text())

_spec = importlib.util.spec_from_file_location("mcp_scanner_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _parse(data) -> list[dict]:
    text = data if isinstance(data, str) else json.dumps(data)
    return wrap.parse_report(
        text, engagement_id="eng_1", run_id="run_1", target_ref="https://tools.acme.test/mcp"
    )


def _findings() -> list[dict]:
    return _parse(FIXTURE)


def _key(f: dict) -> tuple[str, str, str]:
    location = f["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    return f["rule_id"], location, f["severity"]


def _item(findings: dict, **fields) -> dict:
    return {
        "status": "completed",
        "item_type": "tool",
        "tool_name": "t",
        "findings": findings,
        **fields,
    }


def _one(entry) -> dict:
    """A report with one tool and one analyzer entry."""
    return {"scan_results": [_item({"yara_analyzer": entry})]}


def _entry(severity: str, threats: list[str], count: int | None = None, **fields) -> dict:
    total = len(threats) if count is None else count
    return {"severity": severity, "threat_names": threats, "total_findings": total, **fields}


def test_reported_threats_become_schema_valid_findings():
    findings = _findings()
    for f in findings:
        jsonschema.validate(f, SCHEMA)
        assert f["source"] == {
            "tool": "mcp-scanner",
            "version": "4.8.5",
            "native_severity": f["source"]["native_severity"],
        }
        assert f["x-khandaq"]["phase"] == "07-agentic-mcp"
        assert f["target_ref"] == "https://tools.acme.test/mcp"
    assert sorted(_key(f) for f in findings) == sorted([
        ("mcp-scanner.tool-poisoning", "tool:read_file", "high"),
        ("mcp-scanner.data-exfiltration", "tool:send_report", "medium"),
        ("mcp-scanner.prompt-injection", "tool:send_report", "medium"),
        ("mcp-scanner.prompt-injection", "tool:send_report", "high"),  # the API analyzer's
        ("mcp-scanner.code-execution", "prompt:summarise", "info"),
        ("mcp-scanner.credential-harvesting", "resource:file:///srv/app/app.conf", "low"),
    ])  # fmt: skip


def test_safe_errored_and_failed_items_are_not_findings():
    locations = {_key(f)[1] for f in _findings()}
    assert "tool:list_dir" not in locations  # yara SAFE, api errored
    assert "tool:admin_console" not in locations  # the item's scan failed


def test_curated_families_carry_their_framework_ids():
    by_rule = {f["rule_id"]: f for f in _findings()}

    def ids(rule: str) -> set[tuple[str, str]]:
        return {(m["framework"], m["id"]) for m in by_rule[rule]["x-khandaq"]["mappings"]}

    assert ids("mcp-scanner.tool-poisoning") == {("owasp-agentic", "ASI04"), ("atlas", "AML.T0053")}
    assert ("owasp-llm-2026", "LLM01") in ids("mcp-scanner.prompt-injection")
    assert ("owasp-llm-2025", "LLM02") in ids("mcp-scanner.data-exfiltration")
    assert ids("mcp-scanner.code-execution") == {("owasp-agentic", "ASI05")}
    assert ids("mcp-scanner.credential-harvesting") == set()  # uncurated: left to the core table


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("TOOL POISONING", "tool-poisoning"),
        ("PROMPT_INJECTION", "prompt-injection"),
        ("ARBITRARY RESOURCE READ/WRITE", "arbitrary-resource-read-write"),
        ("GENERAL DESCRIPTION-CODE MISMATCH", "general-description-code-mismatch"),
        ("unknown", "unknown"),
        ("  ", "unknown"),
    ],
)
def test_threat_names_become_stable_slugs(name, slug):
    assert wrap.threat_slug(name) == slug


def test_a_repeated_threat_name_is_one_finding():
    report = _one(_entry("HIGH", ["X", "X"], count=2))
    assert len(_parse(report)) == 1


def test_titles_are_bounded():
    entry = _entry("HIGH", ["TOOL POISONING"], threat_summary="s" * 500)
    [f] = _parse(_one(entry))
    assert len(f["title"]) == 200


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ("", "empty"),
        ("  \n", "empty"),
        ('{"scan_results": [', "not valid JSON"),
        ("[]", "no list"),
        ("{}", "no list"),
        ('{"scan_results": {}}', "no list"),
        ('{"scan_results": []}', "nothing was scanned"),
        ({"scan_results": ["x"]}, "not an object"),
        ({"scan_results": [{"status": "completed"}]}, "not an object"),
        (_one("SAFE"), "not an object"),
        (_one(_entry("CRITICAL", ["X"])), "unknown severity"),
        (_one(_entry("HIGH", ["X"], count=-1)), "non-negative"),
        (_one(_entry("HIGH", ["X"], count=True)), "non-negative"),
        (_one(_entry("HIGH", ["X"], count="1")), "non-negative"),
        (_one(_entry("HIGH", [], count=0)), "no findings counted"),
        (_one(_entry("LOW", [], count=2)), "no threat names"),
        (_one(_entry("SAFE", [], count=1)), "no threat names"),
    ],
)  # fmt: skip
def test_untrustworthy_reports_are_refused(data, match):
    with pytest.raises(wrap.ReportError, match=match):
        _parse(data)


@pytest.mark.parametrize(
    "items",
    [
        [_item({}, status="failed"), _item({}, status="skipped")],
        [_item({"yara_analyzer": _entry("UNKNOWN", [], count=0, status="error")})],
        [_item({})],  # no analyzer finished on it
        [_item({"yara_analyzer": _entry("SAFE", [], count=0)}, status="failed")],
    ],
)
def test_a_report_where_nothing_was_scanned_is_refused(items):
    with pytest.raises(wrap.ReportError, match="actually scanned"):
        _parse({"scan_results": items})


def test_a_clean_scan_is_an_empty_finding_set():
    report = _one(_entry("SAFE", [], count=0))
    assert _parse(report) == []


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_an_unscanned_item_emits_no_findings_beside_a_scanned_one(status):
    scanned = _item({"yara_analyzer": _entry("HIGH", ["X"])}, tool_name="scanned")
    unscanned = _item({"yara_analyzer": _entry("HIGH", ["Y"])}, status=status, tool_name="other")
    findings = _parse({"scan_results": [scanned, unscanned]})
    assert {_key(f)[1] for f in findings} == {"tool:scanned"}


def test_an_unscanned_items_entries_are_still_validated():
    scanned = _item({"yara_analyzer": _entry("HIGH", ["X"])})
    broken = _item({"yara_analyzer": _entry("HIGH", [], count=0)}, status="failed")
    with pytest.raises(wrap.ReportError, match="no findings counted"):
        _parse({"scan_results": [scanned, broken]})


def test_a_partial_entry_keeps_its_findings():
    entry = _entry("MEDIUM", ["TOOL POISONING"], status="partial", errors=[{"error": "x"}])
    [f] = _parse({"scan_results": [_item({"llm_analyzer": entry}, status="partial")]})
    assert f["severity"] == "medium"


# --- running the scanner (spec 031) -----------------------------------------------------------------

TARGET = {"type": "mcp_server", "spec": {"url": "https://tools.acme.test/mcp"}}
KEY = "synthetic-mcp-server-key-0123456789"  # synthetic
CLEAN = {
    "server_url": "https://tools.acme.test/mcp",
    "scan_results": [_item({"yara_analyzer": _entry("SAFE", [], 0)})],
}


def _req(target=TARGET, params=None) -> dict:
    return {"engagement_id": "e", "run_id": "r", "target": target, "params": params or {}}


class FakeScanner:
    """Stands in for ``subprocess.run``: records the call and answers as mcp-scanner 4.8.5 does for
    a raw ``remote`` scan, with the report on stdout."""

    def __init__(self, report=FIXTURE, returncode=0):
        self.report, self.returncode, self.calls = report, returncode, []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        out = self.report if isinstance(self.report, bytes) else json.dumps(self.report).encode()
        return subprocess.CompletedProcess(command, self.returncode, stdout=out)


def _run(tmp_path, request, scanner, environ=None):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    environ = {"KHANDAQ_RUN_REQUEST": json.dumps(request), "PATH": "/usr/bin", **(environ or {})}
    return wrap.run(request, evidence=evidence, environ=environ, runner=scanner), evidence


def test_the_built_command_scans_the_in_scope_server_with_yara_only(tmp_path):
    scanner = FakeScanner()
    code, _ = _run(tmp_path, _req(), scanner)
    assert code == 0
    [(command, kwargs)] = scanner.calls
    assert command == [
        "mcp-scanner",
        "--analyzers", "yara",
        "--format", "raw",
        "remote",
        "--server-url", "https://tools.acme.test/mcp",  # the authorised URL, unchanged
    ]  # fmt: skip
    assert kwargs["stdout"] is subprocess.PIPE  # the raw report
    assert kwargs["stderr"] is sys.stderr  # this process's stdout carries only the evidence tar


@pytest.mark.parametrize(
    "target",
    [
        {"type": "llm_endpoint", "spec": {"url": "https://gw.acme.test/v1/chat/completions"}},
        {"type": "agent", "spec": {"host": "agent.acme.test"}},
        {"type": "mcp_server", "spec": {}},
        {"type": "mcp_server", "spec": {"url": "tools.acme.test/mcp"}},
        {"type": "mcp_server", "spec": {"url": "ftp://tools.acme.test/mcp"}},
        {"type": "mcp_server", "spec": {"url": "https://tools.acme.test/mcp#other"}},
        {"type": "mcp_server", "spec": {"url": ["https://tools.acme.test/mcp"]}},
    ],
)
def test_unusable_targets_are_refused_before_the_scanner_runs(tmp_path, target):
    scanner = FakeScanner()
    code, evidence = _run(tmp_path, _req(target), scanner)
    assert code != 0 and scanner.calls == []
    assert list(evidence.iterdir()) == []


@pytest.mark.parametrize(
    "analyzers", [["api"], ["yara", "llm"], "yara,virustotal", [], "", ["YARA"], {"yara": True}]
)
def test_other_analyzers_are_refused_before_the_scanner_runs(tmp_path, analyzers):
    scanner = FakeScanner()
    code, _ = _run(tmp_path, _req(params={"analyzers": analyzers}), scanner)
    assert code != 0 and scanner.calls == []


@pytest.mark.parametrize("analyzers", [["yara"], "yara", " yara ,"])
def test_asking_for_yara_explicitly_is_accepted(tmp_path, analyzers):
    scanner = FakeScanner()
    code, _ = _run(tmp_path, _req(params={"analyzers": analyzers}), scanner)
    assert code == 0 and len(scanner.calls) == 1


def test_the_scanner_environment_carries_no_request_credential_or_analyzer_setting(tmp_path):
    scanner = FakeScanner()
    environ = {
        "KHANDAQ_TARGET_CREDENTIAL": KEY,
        "MCP_SCANNER_API_KEY": "synthetic-not-a-real-key",
        "MCP_SCANNER_LLM_API_KEY": "synthetic-not-a-real-key",
        "MCP_SCANNER_ENDPOINT": "https://elsewhere.test",
        "VIRUSTOTAL_API_KEY": "synthetic-not-a-real-key",
        "HOME": "/tmp",
    }
    code, _ = _run(tmp_path, _req(), scanner, environ)
    assert code == 0
    [(_, kwargs)] = scanner.calls
    assert sorted(kwargs["env"]) == ["HOME", "PATH"]


def test_a_successful_scan_writes_the_report_and_findings_citing_it(tmp_path):
    raw = json.dumps(FIXTURE, indent=2).encode()
    code, evidence = _run(tmp_path, _req(), FakeScanner(raw))
    assert code == 0
    assert sorted(p.name for p in evidence.iterdir()) == ["findings.jsonl", wrap.REPORT_NAME]
    assert (evidence / wrap.REPORT_NAME).read_bytes() == raw  # the tool's report, byte for byte
    findings = [json.loads(line) for line in (evidence / "findings.jsonl").read_text().splitlines()]
    assert len(findings) == 6
    assert {f["target_ref"] for f in findings} == {"https://tools.acme.test/mcp"}
    for f in findings:
        assert f.pop("_evidence_local") == [wrap.REPORT_NAME]
        jsonschema.validate(f, SCHEMA)


def test_a_clean_scan_succeeds_with_no_findings(tmp_path):
    code, evidence = _run(tmp_path, _req(), FakeScanner(CLEAN))
    assert code == 0
    assert (evidence / "findings.jsonl").read_text() == ""
    assert (evidence / wrap.REPORT_NAME).is_file()


@pytest.mark.parametrize(
    "scanner",
    [
        FakeScanner(returncode=1),
        FakeScanner(b""),
        FakeScanner(b"   \n"),
        FakeScanner(b"=== MCP Scanner Results ===\nnot the raw format"),
        FakeScanner({}),
        FakeScanner({"scan_results": []}),
        FakeScanner(b"\xff\xfe not utf-8"),
    ],
    ids=["exit-1", "no-output", "blank", "summary-format", "no-results", "nothing-scanned", "binary"],
)
def test_a_failed_or_untrustworthy_scan_writes_no_findings(tmp_path, scanner):
    code, evidence = _run(tmp_path, _req(), scanner)
    assert code != 0
    assert list(evidence.iterdir()) == []  # never an empty "clean" result, and no report either


def test_the_credential_is_the_bearer_token_and_is_in_no_output(tmp_path, capsys):
    scanner = FakeScanner()
    code, evidence = _run(tmp_path, _req(), scanner, {"KHANDAQ_TARGET_CREDENTIAL": KEY})
    assert code == 0
    [(command, kwargs)] = scanner.calls
    assert command[-2:] == ["--bearer-token", KEY]
    assert command.count(KEY) == 1
    assert KEY not in kwargs["env"].values() and "KHANDAQ_TARGET_CREDENTIAL" not in kwargs["env"]
    captured = capsys.readouterr()
    assert KEY not in captured.out and KEY not in captured.err
    for path in evidence.iterdir():
        assert KEY.encode() not in path.read_bytes(), path.name

    # No credential, or an empty one: no flag at all.
    for environ in ({}, {"KHANDAQ_TARGET_CREDENTIAL": ""}):
        plain = FakeScanner()
        (tmp_path / "evidence" / "findings.jsonl").unlink()
        (tmp_path / "evidence" / wrap.REPORT_NAME).unlink()
        (tmp_path / "evidence").rmdir()
        _run(tmp_path, _req(), plain, environ)
        assert "--bearer-token" not in plain.calls[0][0]


def test_main_reads_the_request_from_the_environment_and_emits_a_tar(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(_req()))
    monkeypatch.setattr(wrap.subprocess, "run", FakeScanner())
    out = io.BytesIO()
    assert wrap.main(tmp_path / "absent.json", evidence, out) == 0
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:") as tar:
        assert sorted(tar.getnames()) == ["findings.jsonl", wrap.REPORT_NAME]


def test_main_emits_nothing_on_stdout_when_the_run_fails(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(_req()))
    monkeypatch.setattr(wrap.subprocess, "run", FakeScanner(returncode=1))
    out = io.BytesIO()
    assert wrap.main(tmp_path / "absent.json", evidence, out) != 0
    assert out.getvalue() == b""


@pytest.mark.parametrize("raw", [None, "not json", "[]", '{"engagement_id": "e"}'])
def test_main_without_a_usable_request_fails(tmp_path, monkeypatch, raw):
    if raw is None:
        monkeypatch.delenv("KHANDAQ_RUN_REQUEST", raising=False)
    else:
        monkeypatch.setenv("KHANDAQ_RUN_REQUEST", raw)
    assert wrap.main(tmp_path / "absent.json", tmp_path, io.BytesIO()) != 0
