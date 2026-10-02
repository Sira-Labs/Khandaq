# Spec 010 — promptfoo adapter

Sprint 4, story S4-3. Depends on: 005, 006. Packages: `adapters/promptfoo/`.

## Goal

An adapter that orchestrates **promptfoo** (OpenAI, MIT) at a pinned version for app-level
scanning/red-teaming. Deliverable (as with garak/PyRIT): image + manifest + a **parser contract test**.
promptfoo writes a single JSON results file; the parser turns each **failed** red-team test (the model
misbehaved / the attack succeeded) into a canonical finding mapped to the frameworks.

## Interface

- `adapters/promptfoo/Dockerfile` — pins `promptfoo` to an exact version.
- `adapters/promptfoo/adapter.yaml` — name, version, phases, frameworks, severity_table, image.
- `adapters/promptfoo/wrap.py` — `parse_report(report_text, *, engagement_id, run_id, target_ref)`
  parses promptfoo JSON results into canonical findings; a failed test becomes a finding.
- `adapters/promptfoo/fixtures/promptfoo-results.json` + `tests/test_contract.py`.

## Behaviour

1. A result with `success: false` (the safety/attack test the model failed) becomes a finding; passing
   results are skipped. Severity comes from the plugin metadata, else a sensible default.
2. `rule_id` is `promptfoo.<pluginId>`; mappings and phase come from the plugin family (prompt-extraction
   → LLM01 + ATLAS; pii → LLM02; harmful → LLM07).
3. The adapter uses only the one in-scope target the control plane passes (spec 005).

## Acceptance criteria

- [x] `Dockerfile` pins promptfoo to `0.118.0`; `make contract-test` passes against the fixture.
- [x] Failed tests become schema-valid, mapped findings (severity from plugin metadata); passing skipped.

> Live promptfoo execution is deploy-verified (needs a Docker daemon + target).

> Fail closed (code review, 2026-10-02): only a failed assertion (`failureReason` 1) is a
> finding; an errored test (`failureReason` 2: provider error, timeout, auth) is not. Empty or
> non-JSON output, no result list, a `stats` count that disagrees with the results, no results,
> or every test errored raises `ReportError`, and `main()` exits non-zero without writing
> `findings.jsonl`. OWASP LLM 2025 ids are added where unambiguous (LLM02 PII, LLM07 prompt
> extraction).

## Out of scope

Live promptfoo execution (deploy-verified); promptfoo's own compliance presets (we map ourselves).
