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
import pytest

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


# --- fail closed (code review, 2026-10-02) -------------------------------------------------------


FIXTURE = (ADAPTER / "fixtures/garak-report.jsonl").read_text().splitlines()


def _parse(lines):
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref="t")


def test_reads_the_garak_0_17_record_shape():
    # garak 0.17 writes total_evaluated/fails, not total; the old parser read `total`, saw 0 and
    # dropped every real result. The fixture is in the 0.17 shape, so this is the regression.
    assert all('"total"' not in line for line in FIXTURE)
    assert len(_parse(FIXTURE)) == 3


def test_legacy_total_field_is_still_read():
    legacy = [
        '{"entry_type":"eval","probe":"dan.X","detector":"d","passed":1,"total":4}',
        '{"entry_type":"completion"}',
    ]
    [f] = _parse(legacy)
    assert f["title"] == "garak: dan.X failed 3/4 (d)" and f["severity"] == "high"


def test_a_truncated_report_is_refused():
    truncated = FIXTURE[:-1] + [FIXTURE[-1][:20]]
    with pytest.raises(wrap.ReportError, match="not valid JSON"):
        _parse(truncated)


def test_a_report_without_completion_is_refused():
    # garak crashed or was killed mid-run: the findings so far are not the run's findings.
    with pytest.raises(wrap.ReportError, match="completion"):
        _parse(FIXTURE[:-1])


def test_records_after_completion_are_refused():
    # A concatenated report must not contribute another (or a partial) run's results.
    with pytest.raises(wrap.ReportError, match="after the completion"):
        _parse(FIXTURE + [FIXTURE[2]])


def test_a_report_with_no_evals_is_refused():
    with pytest.raises(wrap.ReportError, match="no eval"):
        _parse([FIXTURE[0], FIXTURE[1], FIXTURE[-1]])


@pytest.mark.parametrize(
    "record",
    [
        '{"entry_type":"eval","probe":"p","passed":"3","total_evaluated":10}',
        '{"entry_type":"eval","probe":"p","passed":3,"fails":3,"total_evaluated":10}',
        '{"entry_type":"eval","probe":"p","passed":11,"total_evaluated":10}',
        '{"entry_type":"eval","probe":"p","total_evaluated":10}',
    ],
)
def test_malformed_counts_are_refused(record):
    with pytest.raises(wrap.ReportError):
        _parse([record, '{"entry_type":"completion"}'])


def test_every_mapped_family_carries_owasp_llm_2025():
    for family, mapped in wrap.PROBE_FRAMEWORKS.items():
        assert any(fw == "owasp-llm-2025" for fw, _ in mapped), family


def _request(tmp_path):
    req = tmp_path / "run-request.json"
    req.write_text(json.dumps({"engagement_id": "e", "run_id": "r", "target": {"spec": {}}}))
    return req


def test_main_fails_closed_without_a_report(tmp_path):
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()  # never an empty "clean" result


def test_main_fails_closed_on_an_incomplete_report(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text("\n".join(FIXTURE[:-1]))
    assert wrap.main(_request(tmp_path), tmp_path) != 0
    assert not (tmp_path / "findings.jsonl").exists()


def test_main_writes_findings_for_a_complete_report(tmp_path):
    (tmp_path / wrap.REPORT_NAME).write_text("\n".join(FIXTURE))
    assert wrap.main(_request(tmp_path), tmp_path) == 0
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        jsonschema.validate(json.loads(line), SCHEMA)
