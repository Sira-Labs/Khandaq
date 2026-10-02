"""Contract test for the PyRIT adapter (spec 009)."""

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

# Load this adapter's wrap.py in isolation (each adapter ships its own wrap.py).
_spec = importlib.util.spec_from_file_location("pyrit_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _findings():
    lines = (ADAPTER / "fixtures/pyrit-results.jsonl").read_text().splitlines()
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref="gw.acme.test")


def test_successful_attacks_become_schema_valid_findings():
    findings = _findings()
    # crescendo, tap and skeleton_key have outcome "success"; pair failed and the second
    # crescendo errored, so neither is a finding.
    assert len(findings) == 3
    for f in findings:
        jsonschema.validate(f, SCHEMA)
        assert f["severity"] == "high"
        assert f["x-khandaq"]["mappings"]


def test_unsuccessful_attempt_is_skipped():
    rules = {f["rule_id"] for f in _findings()}
    assert "pyrit.pair" not in rules
    assert "pyrit.crescendo" in rules


# --- fail closed and real PyRIT shapes (code review, 2026-10-02) ---------------------------------

FIXTURE = (ADAPTER / "fixtures/pyrit-results.jsonl").read_text().splitlines()
DONE = '{"khandaq":"completion","results":1}'


def _parse(lines):
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref="t")


def _one(record: dict) -> list[dict]:
    return _parse([json.dumps(record), DONE])


def test_an_errored_attack_is_not_a_finding():
    assert len([f for f in _findings() if f["rule_id"] == "pyrit.crescendo"]) == 1


def test_outcome_decides_over_score():
    # PyRIT's AttackResult.outcome is its verdict; a stray score does not override it.
    assert _one({"outcome": "failure", "last_score": {"score_value": "true"}}) == []
    assert len(_one({"outcome": "success", "last_score": {"score_value": "false"}})) == 1


@pytest.mark.parametrize(
    ("score", "found"),
    [
        ({"score_type": "float_scale", "score_value": "0.9"}, True),  # PyRIT serialises a str
        ({"score_type": "float_scale", "score_value": "0.1"}, False),
        ({"score_type": "true_false", "score_value": "True"}, True),
        ({"score_type": "true_false", "score_value": "false"}, False),
        ([{"score_value": "false"}, {"score_value": "0.8"}], True),  # any score achieved
    ],
)
def test_scores_without_an_outcome(score, found):
    assert bool(_one({"attack_strategy": "tap", "last_score": score})) is found


@pytest.mark.parametrize("score", [None, {"score_value": None}, {"score_value": "nan"}, "x", 3])
def test_scores_that_decide_nothing_neither_crash_nor_pass(score):
    # A null score used to crash (None.get); here the run reached no verdict at all.
    with pytest.raises(wrap.ReportError, match="verdict"):
        _one({"attack_strategy": "tap", "last_score": score})


def test_a_truncated_report_is_refused():
    with pytest.raises(wrap.ReportError, match="not valid JSON"):
        _parse(FIXTURE[:2] + [FIXTURE[2][:25]])


def test_a_report_without_completion_is_refused():
    with pytest.raises(wrap.ReportError, match="completion"):
        _parse(FIXTURE[:-1])


def test_a_completion_count_mismatch_is_refused():
    with pytest.raises(wrap.ReportError, match="declares 5"):
        _parse(FIXTURE[:2] + FIXTURE[-1:])


def test_an_empty_run_is_refused():
    with pytest.raises(wrap.ReportError, match="empty"):
        _parse(['{"khandaq":"completion","results":0}'])


def test_every_strategy_carries_owasp_llm_2025():
    for mapped in [*wrap.STRATEGY_FRAMEWORKS.values(), wrap.DEFAULT_FRAMEWORKS]:
        assert any(fw == "owasp-llm-2025" for fw, _ in mapped)


def _request(tmp_path):
    req = tmp_path / "run-request.json"
    req.write_text(json.dumps({"engagement_id": "e", "run_id": "r", "target": {"spec": {}}}))
    return req


def test_main_fails_closed_without_results(tmp_path):
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


def test_main_writes_findings_for_complete_results(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text("\n".join(FIXTURE))
    assert wrap.main(_request(tmp_path), tmp_path) == 0
    assert len((tmp_path / "findings.jsonl").read_text().splitlines()) == 3
