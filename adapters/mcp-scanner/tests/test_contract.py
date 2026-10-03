"""Contract test for the Cisco mcp-scanner adapter (spec 025)."""

from __future__ import annotations

import importlib.util
import json
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


def _request(tmp_path: Path, spec: dict | None = None) -> Path:
    req = tmp_path / "run-request.json"
    target = {"type": "mcp_server", "spec": spec or {"url": "https://tools.acme.test/mcp"}}
    req.write_text(json.dumps({"engagement_id": "e", "run_id": "r", "target": target}))
    return req


def test_main_fails_closed_without_a_report(tmp_path):
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


@pytest.mark.parametrize("text", ["", "{}", '{"scan_results": []}'])
def test_main_fails_closed_on_an_untrustworthy_report(tmp_path, text):
    (tmp_path / wrap.REPORT_NAME).write_text(text)
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


def test_main_writes_findings_for_a_complete_report(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text(json.dumps(FIXTURE))
    assert wrap.main(_request(tmp_path), tmp_path) == 0
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 6
    assert {json.loads(line)["target_ref"] for line in lines} == {"https://tools.acme.test/mcp"}


def test_main_names_an_agent_target_by_host(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text(json.dumps(FIXTURE))
    assert wrap.main(_request(tmp_path, {"host": "agent.acme.test"}), tmp_path) == 0
    first = json.loads((tmp_path / "findings.jsonl").read_text().splitlines()[0])
    assert first["target_ref"] == "agent.acme.test"
