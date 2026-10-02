"""Contract test for the PyRIT adapter (spec 009)."""

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
_spec = importlib.util.spec_from_file_location("pyrit_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _findings():
    lines = (ADAPTER / "fixtures/pyrit-results.jsonl").read_text().splitlines()
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref="gw.acme.test")


def test_successful_attacks_become_schema_valid_findings():
    findings = _findings()
    # crescendo (true), tap (0.9), skeleton_key ("success") succeed; pair (false) is skipped.
    assert len(findings) == 3
    for f in findings:
        jsonschema.validate(f, SCHEMA)
        assert f["severity"] == "high"
        assert f["x-khandaq"]["mappings"]


def test_unsuccessful_attempt_is_skipped():
    rules = {f["rule_id"] for f in _findings()}
    assert "pyrit.pair" not in rules
    assert "pyrit.crescendo" in rules
