"""Contract test for the ART adapter (spec 033).

The fixture was recorded from a real ART 1.20.1 run on a synthetic scikit-learn classifier, so the
field shapes (parameter names, estimator name, ART's success rate) are the tool's own.
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
_spec = importlib.util.spec_from_file_location("art_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)

FIXTURE = (ADAPTER / "fixtures/art-results.jsonl").read_text().splitlines()
DIGEST = "sha256:" + "ab" * 32
DONE = '{"khandaq":"completion","results":1}'
RESULT = json.loads(FIXTURE[0])


def _parse(lines: list[str]) -> list[dict]:
    return wrap.parse_report(lines, engagement_id="eng_1", run_id="run_1", target_ref=DIGEST)


def _one(**changes: object) -> list[dict]:
    return _parse([json.dumps({**RESULT, **changes}), DONE])


def test_fixture_findings_are_schema_valid():
    findings = _parse(FIXTURE)
    # Four attacks were evaluated; FastGradientMethod with a negligible eps changed nothing.
    assert [f["rule_id"] for f in findings] == [
        "art.evasion.fastgradientmethod",
        "art.evasion.projectedgradientdescent",
        "art.evasion.hopskipjump",
    ]
    for f in findings:
        jsonschema.validate(f, SCHEMA)
        assert f["x-khandaq"]["phase"] == "05-adversarial-ml"
        assert f["source"] == {"tool": "art", "version": "1.20.1", "native_severity": "high"}
        assert f["severity"] == "high" and f["target_ref"] == DIGEST
        assert f["x-khandaq"]["mappings"] == [
            {"framework": "atlas", "id": "AML.T0015"},
            {"framework": "atlas", "id": "AML.T0043"},
            {"framework": "nist-ai-rmf", "id": "MEASURE-2.7"},
        ]
    first = findings[0]
    assert first["locations"] == [
        {"logicalLocations": [{"fullyQualifiedName": "art.attacks.evasion.FastGradientMethod"}]}
    ]
    # ART's own numbers are in the title: every prediction changed, accuracy 0.845 → 0.155.
    assert "100.0% of 200 samples" in first["title"] and "eps=0.3" in first["title"]
    assert "0.845 → 0.155" in first["title"]


@pytest.mark.parametrize(
    ("rate", "severity"),
    [
        (1.0, "high"),
        (0.5, "high"),
        (0.49, "medium"),
        (0.2, "medium"),
        (0.19, "low"),
        (0.005, "low"),
    ],
)
def test_severity_follows_the_success_rate(rate, severity):
    [finding] = _one(success_rate=rate)
    assert finding["severity"] == severity
    assert finding["source"]["native_severity"] == severity


def test_an_attack_without_effect_is_skipped():
    assert _one(success_rate=0) == []
    # ART's success rate decides, not the accuracies: a two-class model whose every prediction
    # flips can end with a *higher* accuracy than it started with.
    [finding] = _one(success_rate=1.0, clean_accuracy=0.2, adversarial_accuracy=0.8)
    assert finding["severity"] == "high"


def test_the_same_attack_is_one_rule_whatever_its_parameters():
    weak = _one(params={"eps": 0.01, "norm": "inf"}, success_rate=0.1)[0]
    strong = _one(params={"eps": 0.3, "norm": "inf"}, success_rate=0.9)[0]
    assert weak["rule_id"] == strong["rule_id"] and weak["locations"] == strong["locations"]
    assert weak["severity"] == "low" and strong["severity"] == "high"


def test_a_targeted_attack_is_worded_as_one():
    [finding] = _one(params={"eps": 0.3, "targeted": True}, success_rate=0.4)
    assert "reached the target class on 40.0%" in finding["title"]


@pytest.mark.parametrize(
    ("lines", "reason"),
    [
        ([], "no completion record"),
        ([json.dumps(RESULT)], "no completion record"),
        ([DONE.replace("1", "0")], "empty"),
        ([json.dumps(RESULT), DONE.replace("1", "2")], "declares 2 results, found 1"),
        ([json.dumps(RESULT), DONE, json.dumps(RESULT)], "after the completion record"),
        ([json.dumps(RESULT), DONE, DONE], "second completion record"),
        ([json.dumps(RESULT)[:-20], DONE], "not valid JSON"),
        (["[1, 2]", DONE], "not a JSON object"),
        ([json.dumps(RESULT), '{"khandaq":"completion","results":true}'], "no result count"),
    ],
)
def test_incomplete_results_fail_closed(lines, reason):
    with pytest.raises(wrap.ReportError, match=reason):
        _parse(lines)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"success_rate": None}, "'success_rate' is not a number"),
        ({"success_rate": "0.9"}, "'success_rate' is not a number"),
        ({"success_rate": True}, "'success_rate' is not a number"),
        ({"success_rate": 1.5}, "not between 0 and 1"),
        ({"success_rate": -0.1}, "not between 0 and 1"),
        ({"success_rate": float("nan")}, "not between 0 and 1"),
        ({"clean_accuracy": 2}, "'clean_accuracy' is not between 0 and 1"),
        ({"adversarial_accuracy": None}, "'adversarial_accuracy' is not a number"),
        ({"samples": 0}, "'samples' is not a positive integer"),
        ({"samples": 200.0}, "'samples' is not a positive integer"),
        ({"samples": True}, "'samples' is not a positive integer"),
        ({"attack": ""}, "'attack' is missing"),
        ({"attack": None}, "'attack' is missing"),
        ({"attack_module": None}, "'attack_module' is missing"),
        ({"art_version": "1.19.0"}, "not 1.20.1"),
        ({"art_version": None}, "not 1.20.1"),
    ],
)
def test_malformed_results_fail_closed(changes, reason):
    with pytest.raises(wrap.ReportError, match=reason):
        _one(**changes)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"family": "inference"}, "not one this adapter reads"),
        ({"family": "poisoning"}, "not one this adapter reads"),
        ({"family": None}, "'family' is missing"),
        # A result that calls itself evasion but comes from another part of ART.
        ({"attack_module": "art.attacks.inference.membership_inference"}, "not an ART evasion"),
        ({"attack_module": "art.attacks.evasion_lookalike.x"}, "not an ART evasion"),
        ({"attack_module": "someone.elses.attack"}, "not an ART evasion"),
    ],
)
def test_only_the_evasion_family_is_read(changes, reason):
    with pytest.raises(wrap.ReportError, match=reason):
        _one(**changes)


def _request(tmp_path: Path, spec: dict) -> Path:
    path = tmp_path / "run-request.json"
    path.write_text(
        json.dumps(
            {
                "run_id": "run_1",
                "engagement_id": "eng_1",
                "target": {"type": "model_artifact", "spec": spec},
                "params": {},
            }
        )
    )
    return path


def test_translate_writes_findings_or_exits_2(tmp_path, capsys):
    request = json.loads(_request(tmp_path, {"digest": DIGEST}).read_text())
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    assert wrap.translate(request, evidence) == 2  # no results: ART did not run
    assert "is missing" in capsys.readouterr().err
    assert not (evidence / "findings.jsonl").exists()

    (evidence / wrap.REPORT_NAME).write_text(FIXTURE[0] + "\n")  # no completion record
    assert wrap.translate(request, evidence) == 2
    assert "refusing untrustworthy results" in capsys.readouterr().err
    assert not (evidence / "findings.jsonl").exists()

    (evidence / wrap.REPORT_NAME).write_text("\n".join(FIXTURE) + "\n")
    assert wrap.translate(request, evidence) == 0
    written = [json.loads(x) for x in (evidence / "findings.jsonl").read_text().splitlines()]
    assert len(written) == 3 and all(f["target_ref"] == DIGEST for f in written)

    # A later call on the same directory that fails leaves no findings of the earlier one behind.
    (evidence / wrap.REPORT_NAME).write_text(FIXTURE[0] + "\n")
    assert wrap.translate(request, evidence) == 2
    assert not (evidence / "findings.jsonl").exists()
    (evidence / wrap.REPORT_NAME).unlink()
    (evidence / "findings.jsonl").write_text("stale\n")
    assert wrap.translate(request, evidence) == 2
    assert not (evidence / "findings.jsonl").exists()
    # And a valid report writes its complete findings again.
    (evidence / wrap.REPORT_NAME).write_text("\n".join(FIXTURE) + "\n")
    assert wrap.translate(request, evidence) == 0
    assert len((evidence / "findings.jsonl").read_text().splitlines()) == 3


@pytest.mark.parametrize(
    ("spec", "ref"),
    [
        ({"digest": DIGEST, "location": "registry.test/models/fraud:3"}, DIGEST),
        ({"location": "registry.test/models/fraud:3"}, "registry.test/models/fraud:3"),
        ({}, "target"),
    ],
)
def test_the_target_is_named_by_its_digest(spec, ref):
    assert wrap.target_ref({"target": {"type": "model_artifact", "spec": spec}}) == ref
