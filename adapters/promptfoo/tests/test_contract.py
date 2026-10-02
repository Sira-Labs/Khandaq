"""Contract test for the promptfoo adapter (spec 010)."""

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

_spec = importlib.util.spec_from_file_location("promptfoo_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _findings():
    text = (ADAPTER / "fixtures/promptfoo-results.json").read_text()
    return wrap.parse_report(text, engagement_id="eng_1", run_id="run_1", target_ref="gw.acme.test")


def test_failed_tests_become_schema_valid_findings():
    findings = _findings()
    assert len(findings) == 3  # 3 failed, 1 passed, 1 errored (neither is a finding)
    for f in findings:
        jsonschema.validate(f, SCHEMA)
        assert f["x-khandaq"]["mappings"]


def test_severity_and_mapping_by_plugin():
    by_rule = {f["rule_id"]: f for f in _findings()}
    assert by_rule["promptfoo.harmful:hate"]["severity"] == "high"
    assert any(m["id"] == "LLM02" for m in by_rule["promptfoo.pii:direct"]["x-khandaq"]["mappings"])
    assert any(m["id"] == "LLM01" for m in by_rule["promptfoo.prompt-extraction"]["x-khandaq"]["mappings"])


def test_passing_test_is_skipped():
    assert "promptfoo.harmful:self-harm" not in {f["rule_id"] for f in _findings()}


# --- fail closed and real promptfoo shapes (code review, 2026-10-02) -----------------------------

FIXTURE = json.loads((ADAPTER / "fixtures/promptfoo-results.json").read_text())


def _parse(data) -> list[dict]:
    text = data if isinstance(data, str) else json.dumps(data)
    return wrap.parse_report(text, engagement_id="eng_1", run_id="run_1", target_ref="t")


def _with(results: list[dict]) -> dict:
    return {"results": {"version": 3, "results": results}}


def test_an_errored_test_is_not_a_finding():
    # A provider timeout (failureReason 2) used to become a "vulnerability".
    assert "promptfoo.pii:session" not in {f["rule_id"] for f in _findings()}
    legacy = {"success": False, "error": "connect ECONNREFUSED", "testCase": {}}
    passed = {"success": True, "testCase": {}}
    assert _parse(_with([legacy, passed])) == []


def test_null_plugin_and_severity_fall_back():
    meta = {"pluginId": None, "severity": None}
    [f] = _parse(_with([{"success": False, "failureReason": 1, "testCase": {"metadata": meta}}]))
    assert f["rule_id"] == "promptfoo.unknown" and f["severity"] == "medium"


def test_plugin_id_from_result_metadata():
    res = {"success": False, "failureReason": 1, "metadata": {"pluginId": "pii:api-db"}}
    [f] = _parse(_with([res]))
    assert f["rule_id"] == "promptfoo.pii:api-db"


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("", "empty"),
        ("   \n", "empty"),
        ('{"results": {"results": [', "not valid JSON"),
        ("{}", "no list"),
        ('{"results": {"results": "x"}}', "no list"),
        ('{"results": {"results": []}}', "no results"),
        ('{"results": {"results": [{"failureReason": 1}]}}', "boolean"),
    ],
)
def test_untrustworthy_output_is_refused(text, match):
    with pytest.raises(wrap.ReportError, match=match):
        _parse(text)


@pytest.mark.parametrize(
    "res",
    [
        {"success": False, "failureReason": 0},  # failed, yet "no failure": would vanish
        {"success": True, "failureReason": 1},
        {"success": False, "failureReason": 3},  # a code this parser does not know
        {"success": False, "failureReason": "1"},
        {"success": False, "failureReason": True},
    ],
)
def test_contradictory_or_unknown_failure_reasons_are_refused(res):
    with pytest.raises(wrap.ReportError, match="failureReason"):
        _parse(_with([res]))


def test_stats_mismatch_is_refused():
    data = json.loads(json.dumps(FIXTURE))
    data["results"]["results"].pop()  # the output lost a result its stats still count
    with pytest.raises(wrap.ReportError, match="stats"):
        _parse(data)


def test_a_run_where_every_test_errored_is_refused():
    errored = {"success": False, "failureReason": 2, "error": "401 Unauthorized", "testCase": {}}
    with pytest.raises(wrap.ReportError, match="errored"):
        _parse(_with([errored, errored]))


def test_owasp_llm_2025_where_the_category_is_unambiguous():
    by_rule = {f["rule_id"]: f for f in _findings()}
    expected_ids = (("promptfoo.pii:direct", "LLM02"), ("promptfoo.prompt-extraction", "LLM07"))
    for rule, expected in expected_ids:
        ids = {(m["framework"], m["id"]) for m in by_rule[rule]["x-khandaq"]["mappings"]}
        assert ("owasp-llm-2025", expected) in ids


def _request(tmp_path):
    req = tmp_path / "run-request.json"
    req.write_text(json.dumps({"engagement_id": "e", "run_id": "r", "target": {"spec": {}}}))
    return req


def test_main_fails_closed_without_output(tmp_path):
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


def test_main_fails_closed_on_empty_output(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text("")
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


def test_main_writes_findings_for_complete_output(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text(json.dumps(FIXTURE))
    assert wrap.main(_request(tmp_path), tmp_path) == 0
    assert len((tmp_path / "findings.jsonl").read_text().splitlines()) == 3
