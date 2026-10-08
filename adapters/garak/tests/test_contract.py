"""Contract test for the garak adapter (spec 006).

Parses the recorded garak fixture and asserts every emitted finding validates against the canonical
`finding.schema.json` and carries framework mappings. This catches an upstream format change without
running garak or a container. Needs `jsonschema` (pure Python).
"""

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

# Load this adapter's wrap.py in isolation (each adapter ships its own wrap.py).
_spec = importlib.util.spec_from_file_location("garak_wrap", ADAPTER / "wrap.py")
wrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrap)


def _findings():
    lines = (ADAPTER / "fixtures/garak-report.jsonl").read_text().splitlines()
    return wrap.parse_report(
        lines, engagement_id="eng_1", run_id="run_1", target_ref="gw.acme.test"
    )


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


DIGEST = '{"entry_type": "digest", "meta": {}, "eval": {}}'


def test_garak_0_17_digest_after_completion_is_accepted():
    # A real garak 0.17.0 run (spec 027) appends one `digest` record after `completion`.
    assert len(_parse(FIXTURE + [DIGEST])) == 3


@pytest.mark.parametrize("tail", [[DIGEST, DIGEST], [DIGEST, FIXTURE[2]]])
def test_anything_beyond_one_digest_after_completion_is_refused(tail):
    with pytest.raises(wrap.ReportError, match="after the completion"):
        _parse(FIXTURE + tail)


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


# --- running garak in the sandbox (spec 027) -----------------------------------------------------

TARGET = {
    "type": "llm_endpoint",
    "spec": {"url": "http://demo-target:8080/v1/chat/completions", "model": "demo-model"},
}


def _req(target=TARGET, params=None):
    return {"engagement_id": "e", "run_id": "r", "target": target, "params": params or {}}


class FakeGarak:
    """Stands in for ``subprocess.run``: records the call and writes a garak report where garak
    0.17 would (``$XDG_DATA_HOME/garak/garak_runs/<prefix>.report.jsonl``)."""

    def __init__(self, report=FIXTURE, returncode=0, hitlog=True):
        self.report, self.returncode, self.hitlog, self.calls = report, returncode, hitlog, []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        runs = Path(kwargs["env"]["XDG_DATA_HOME"]) / "garak" / "garak_runs"
        runs.mkdir(parents=True, exist_ok=True)
        if self.report is not None:
            (runs / "khandaq.report.jsonl").write_text("\n".join(self.report))
        if self.hitlog:
            (runs / "khandaq.hitlog.jsonl").write_text('{"probe": "p"}\n')
        return subprocess.CompletedProcess(command, self.returncode)


def _run(tmp_path, request, garak):
    evidence, scratch = tmp_path / "evidence", tmp_path / "scratch"
    evidence.mkdir()
    scratch.mkdir()
    environ = {"KHANDAQ_RUN_REQUEST": json.dumps(request), "PATH": "/usr/bin"}
    code = wrap.run(request, evidence=evidence, scratch=scratch, environ=environ, runner=garak)
    return code, evidence, scratch


def test_the_built_command_targets_the_in_scope_endpoint_only(tmp_path):
    garak = FakeGarak()
    code, _, scratch = _run(tmp_path, _req(), garak)
    assert code == 0
    [(command, kwargs)] = garak.calls
    assert command[1:] == [
        "-m", "garak",
        "--target_type", "openai.OpenAICompatible",
        "--target_name", "demo-model",
        "--generator_option_file", str(scratch / "generator.json"),
        "--probes", ",".join(wrap.DEFAULT_PROBES),
        "--generations", "1",
        "--parallel_attempts", "1",
        "--report_prefix", "khandaq",
    ]  # fmt: skip
    # garak appends chat/completions to the base URI: the request path is the authorised URL.
    options = json.loads((scratch / "generator.json").read_text())
    assert options == {"openai": {"OpenAICompatible": {"uri": "http://demo-target:8080/v1/"}}}
    env = kwargs["env"]
    assert "KHANDAQ_RUN_REQUEST" not in env  # garak does not need to see the request
    assert env["XDG_DATA_HOME"].startswith(str(scratch))  # the rootfs is read-only
    assert env["OPENAICOMPATIBLE_API_KEY"] == wrap.PLACEHOLDER_KEY
    assert kwargs["stdout"] is sys.stderr  # stdout carries only the evidence tar


def test_a_trailing_slash_and_port_keep_the_authorised_base(tmp_path):
    target = {
        "type": "agent",
        "spec": {"url": "https://gw.test:8443/api/v1/chat/completions/", "model": "m"},
    }
    assert wrap.generator_target(target) == ("https://gw.test:8443/api/v1/", "m")


def test_a_successful_run_writes_findings_with_evidence(tmp_path):
    code, evidence, _ = _run(tmp_path, _req(), FakeGarak())
    assert code == 0
    assert sorted(p.name for p in evidence.iterdir()) == [
        "findings.jsonl", "garak-hitlog.jsonl", "garak-report.jsonl",
    ]  # fmt: skip
    findings = [json.loads(line) for line in (evidence / "findings.jsonl").read_text().splitlines()]
    assert len(findings) == 3
    for f in findings:
        assert f.pop("_evidence_local") == ["garak-report.jsonl", "garak-hitlog.jsonl"]
        jsonschema.validate(f, SCHEMA)


@pytest.mark.parametrize(
    ("probes", "expected"),
    [
        (["promptinject"], "promptinject"),
        ("dan.Dan_11_0, promptinject", "dan.Dan_11_0,promptinject"),
        (["xss", "xss"], "xss"),
    ],
)
def test_requested_probes_are_passed_by_name(tmp_path, probes, expected):
    garak = FakeGarak()
    assert _run(tmp_path, _req(params={"probes": probes}), garak)[0] == 0
    command = garak.calls[0][0]
    assert command[command.index("--probes") + 1] == expected


@pytest.mark.parametrize(
    "probes",
    [[], "", ["--config=/x"], ["promptinject;rm"], ["a.b.c"], [f"p{i}" for i in range(11)], [7]],
)
def test_malformed_probe_selections_are_refused_before_garak_runs(tmp_path, probes):
    garak = FakeGarak()
    code, evidence, _ = _run(tmp_path, _req(params={"probes": probes}), garak)
    assert code != 0 and garak.calls == [] and not (evidence / "findings.jsonl").exists()


@pytest.mark.parametrize(
    "target",
    [
        {"type": "mcp_server", "spec": {"url": "http://demo-target:8080/mcp"}},
        {
            "type": "llm_endpoint",
            "spec": {"url": "http://demo-target:8080/v1/completions", "model": "m"},
        },
        {"type": "llm_endpoint", "spec": {"url": "http://demo-target:8080/v1/chat/completions"}},
        {"type": "llm_endpoint", "spec": {"host": "demo-target", "model": "m"}},
        {"type": "llm_endpoint", "spec": {"url": "file:///v1/chat/completions", "model": "m"}},
        # The parsed path must be the chat endpoint: a query or fragment cannot fake it.
        {
            "type": "llm_endpoint",
            "spec": {"url": "http://h/other?next=/chat/completions", "model": "m"},
        },
        {"type": "llm_endpoint", "spec": {"url": "http://h/v1/chat/completions?x=1", "model": "m"}},
        {"type": "llm_endpoint", "spec": {"url": "http://h/other#/chat/completions", "model": "m"}},
        {"type": "llm_endpoint", "spec": {"url": "http:///v1/chat/completions", "model": "m"}},
    ],
)
def test_unusable_targets_are_refused_before_garak_runs(tmp_path, target):
    garak = FakeGarak()
    code, evidence, _ = _run(tmp_path, _req(target=target), garak)
    assert code != 0 and garak.calls == [] and not (evidence / "findings.jsonl").exists()


@pytest.mark.parametrize(
    "garak",
    [FakeGarak(returncode=1), FakeGarak(report=None), FakeGarak(report=FIXTURE[:-1])],
    ids=["garak-failed", "no-report", "incomplete-report"],
)
def test_a_failed_garak_run_writes_no_findings(tmp_path, garak):
    code, evidence, _ = _run(tmp_path, _req(), garak)
    assert code != 0
    assert not (evidence / "findings.jsonl").exists()  # never an empty "clean" result


def test_main_reads_the_request_from_the_environment_and_emits_a_tar(tmp_path, monkeypatch):
    evidence, scratch = tmp_path / "evidence", tmp_path / "scratch"
    evidence.mkdir()
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(_req()))
    monkeypatch.setattr(wrap.subprocess, "run", FakeGarak())
    out = io.BytesIO()
    assert wrap.main(tmp_path / "absent.json", evidence, scratch, out) == 0
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:") as tar:
        assert sorted(tar.getnames()) == [
            "findings.jsonl",
            "garak-hitlog.jsonl",
            "garak-report.jsonl",
        ]


def test_main_emits_nothing_on_stdout_when_the_run_fails(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setenv("KHANDAQ_RUN_REQUEST", json.dumps(_req()))
    monkeypatch.setattr(wrap.subprocess, "run", FakeGarak(returncode=1))
    out = io.BytesIO()
    assert wrap.main(tmp_path / "absent.json", evidence, tmp_path / "scratch", out) != 0
    assert out.getvalue() == b""


def test_main_without_a_request_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("KHANDAQ_RUN_REQUEST", raising=False)
    assert wrap.main(tmp_path / "absent.json", tmp_path, tmp_path / "scratch", io.BytesIO()) != 0
