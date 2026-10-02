# Spec 006 — garak adapter (first real adapter)

Sprint 3, story S3-2. Depends on: 005. Packages: `adapters/garak/`.

## Goal

The first production adapter wraps **garak** (NVIDIA, Apache-2.0) at an exact pinned version, runs it
against an authorised `llm_endpoint` target inside the run sandbox, and translates its JSONL output into
canonical findings with severity and framework mappings. It ships a contract test against a recorded
garak fixture so an upstream change fails CI rather than corrupting findings. This proves the
orchestrate-not-reimplement model end to end.

## User story

As an operator, I want to run garak against an authorised LLM endpoint and see its results in the
unified findings inbox, mapped to OWASP and ATLAS, with evidence sealed.

## Interface

- `adapters/garak/Dockerfile` — pins garak to an exact version.
- `adapters/garak/adapter.yaml` — `name: garak`, `version: <pinned>`, `phases: [03-scanning, 04-prompt-injection]`,
  `frameworks:` the IDs it can emit, `severity_table:` garak probe outcome → canonical severity.
- `adapters/garak/wrap.py` — reads the run-request, invokes garak against the target, parses its JSONL
  report, emits canonical findings JSONL + the raw report as evidence.
- `adapters/garak/tests/` + a recorded `fixtures/garak-report.jsonl`.

## Behaviour

1. The adapter consumes only the run-request target + params the control plane passes (already
   scope-checked); it reaches no other host (egress contained by spec 005 / ADR-0009).
2. garak runs with a configured probe set; its JSONL is parsed; each failing probe becomes a canonical
   finding with `rule_id = garak.<probe>`, a title, the garak native outcome mapped to severity, and
   the framework mappings from the core tables; the full garak report is stored as evidence.
3. Secrets (the endpoint credential) are injected ephemerally and never written to findings/evidence in
   the clear (redaction, ADR-0006).
4. The contract test runs the adapter's parser over the recorded fixture and asserts every emitted
   finding validates against `finding.schema.json` and carries required mappings.

## Acceptance criteria

- [x] `Dockerfile` pins garak to an exact version; `make contract-test` passes against the recorded
      fixture (3 schema-valid findings; `make build` builds the image in CI/release, not in unit CI).
- [~] Running the adapter end to end against a target yields inbox findings with sealed evidence —
      **deploy-verified**: needs a Docker daemon. The echo pipeline (spec 005) already proves the
      inbox/dedup/seal path; the garak **parser** is contract-tested here.
- [x] The adapter reaches no host but the authorised target: the run request carries only that one
      target (spec 005 test); `wrap.py` uses only `request["target"]`.
- [x] Endpoint credentials never appear in findings: the parser emits only probe/detector/severity +
      mappings (no credential fields); credentials are injected ephemerally at runtime and redacted in
      the evidence path (ADR-0006).

> Notes (per CLAUDE.md): the report **parser** (`wrap.py:parse_report`) is the contract-tested unit;
> `main()` (run garak in the container, write evidence) needs a Docker daemon + live target and is
> deploy-verified. The image publishes from `release.yml`. Wiring disk-manifest adapters into the live
> API registry + Docker execution on the worker is a follow-up (the api registry is builtin-only today).

> Fail closed (code review, 2026-10-02): the parser reads garak 0.17's `passed`/`fails`/
> `total_evaluated` (the fixture was re-recorded in that shape; it had used a `total` field garak
> 0.17 does not write, so real reports yielded no findings). A truncated line, a report without
> garak's `completion` record, or one with no eval records raises `ReportError`; `main()` then
> exits non-zero and writes no `findings.jsonl`. `main()` still expects the report to be present:
> invoking garak in the sandbox is part of the Docker-execution follow-up above.

## Test cases

Adapter contract (`adapters/garak/tests/test_contract.py`): parse fixture → all findings schema-valid +
mapped. Integration: a run against a mock endpoint produces inbox findings + sealed evidence.

## Out of scope

PyRIT and promptfoo adapters (specs 009–010, same pattern); tuning garak's probe selection per suite
(suite definitions, later).
