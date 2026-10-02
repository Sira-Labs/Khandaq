"""Contract test for the garak adapter (spec 006).

Parses the recorded garak fixture and asserts every emitted finding validates against the canonical
`finding.schema.json` and carries framework mappings. This catches an upstream format change without
running garak or a container. Needs `jsonschema` (pure Python).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import jsonschema

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent
REPO = HERE.parents[2]
SCHEMA = json.loads((REPO / "core/khandaq-core/schema/finding.schema.json").read_text())

# Load this adapter's wrap.py in isolation (each adapter ships its own wrap.py).
_spec = importlib.util.spec_from_file_location("garak_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _findings():
    lines = (ADAPTER / "fixtures/garak-report.jsonl").read_text().splitlines()
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref="gw.acme.test")


def test_findings_validate_against_schema():
    findings = _findings()
    # 3 failing probes become findings; the fully-passing probe is skipped.
    assert len(findings) == 3
    for f in findings:
        jsonschema.validate(f, SCHEMA)


def test_findings_carry_mappings_and_severities():
    findings = _findings()
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["garak.dan.dan_11_0"]["severity"] == "high"  # 0/8 passed
    assert by_rule["garak.leakreplay.literaturecloze"]["severity"] == "low"  # 9/10 passed
    hijack = by_rule["garak.promptinject.hijackhatehumans"]
    assert hijack["severity"] == "high"  # 3/10 passed → 0.7 fail rate
    assert any(m["id"] == "LLM01" for m in hijack["x-khandaq"]["mappings"])
    # every finding has at least one framework mapping
    assert all(f["x-khandaq"]["mappings"] for f in findings)


def test_passing_probe_is_not_a_finding():
    rules = {f["rule_id"] for f in _findings()}
    assert "garak.test.blank" not in rules
