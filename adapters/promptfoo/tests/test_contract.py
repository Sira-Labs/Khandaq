"""Contract test for the promptfoo adapter (spec 010)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import jsonschema

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
    assert len(findings) == 3  # 3 failed, 1 passed (skipped)
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
