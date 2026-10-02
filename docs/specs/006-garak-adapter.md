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

- [ ] `make build` builds the pinned image; `make contract-test` passes against the fixture.
- [ ] Running the adapter against the bundled local target (spec 007 test target / a mock) yields
      canonical findings in the inbox, deduped, mapped, with sealed evidence.
- [ ] The adapter reaches no host but the authorised target (reuses the spec 005 egress test).
- [ ] Endpoint credentials never appear in findings, evidence shown in UI, or logs (test).

## Test cases

Adapter contract (`adapters/garak/tests/test_contract.py`): parse fixture → all findings schema-valid +
mapped. Integration: a run against a mock endpoint produces inbox findings + sealed evidence.

## Out of scope

PyRIT and promptfoo adapters (specs 009–010, same pattern); tuning garak's probe selection per suite
(suite definitions, later).
