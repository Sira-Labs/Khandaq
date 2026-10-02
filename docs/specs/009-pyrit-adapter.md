# Spec 009 — PyRIT adapter

Sprint 4, story S4-2. Depends on: 005, 006. Packages: `adapters/pyrit/`.

## Goal

An adapter that orchestrates **PyRIT** (Microsoft, MIT) at a pinned version for the prompt-injection
phase. Like garak (spec 006), the deliverable is the image + manifest + a **parser contract test**: a
recorded PyRIT results fixture is translated into canonical findings that validate against the schema
and carry framework mappings. Real execution (run PyRIT against a target in a container) is
deploy-verified.

## Interface

- `adapters/pyrit/Dockerfile` — pins `pyrit` to an exact version.
- `adapters/pyrit/adapter.yaml` — name, version, `phases: [04-prompt-injection]`, frameworks,
  severity_table, image.
- `adapters/pyrit/wrap.py` — `parse_report(lines, *, engagement_id, run_id, target_ref)` turns PyRIT
  scored-conversation records into canonical findings; a successful jailbreak/injection is a finding.
- `adapters/pyrit/fixtures/pyrit-results.jsonl` + `adapters/pyrit/tests/test_contract.py`.

## Behaviour

1. Each PyRIT record carries an attack strategy, an objective, and a score. A record whose score
   indicates the objective was achieved (a successful attack) becomes a finding; unsuccessful attempts
   are skipped.
2. Severity reflects a successful jailbreak (high); rule id is `pyrit.<strategy>`; mappings come from the
   strategy (prompt-injection → OWASP LLM01 + ATLAS).
3. The adapter uses only the one in-scope target the control plane passes (spec 005).

## Acceptance criteria

- [x] `Dockerfile` pins PyRIT to `1.1.0`; `make contract-test` passes against the fixture.
- [x] Parsed findings validate against `finding.schema.json` and carry framework mappings.
- [x] Successful attacks (true / score ≥ 0.5 / "success") become findings; unsuccessful ones are skipped.

> Live PyRIT execution is deploy-verified (needs a Docker daemon + target). Adapter contract tests run
> with `--import-mode=importlib` so each adapter's `wrap.py` loads in isolation.

> Fail closed (code review, 2026-10-02): each line is a PyRIT `AttackResult`
> (`model_dump(mode="json")` + the wrapper's `attack_strategy`), closed by
> `{"khandaq": "completion", "results": N}`. `outcome` decides (`success` → finding; `error`/
> `undetermined` decide nothing); without one the `last_score` string value decides ("true", or a
> float ≥ 0.5). A truncated line, a missing or mismatched completion record, an empty run, or a
> run where no attack reached a verdict raises `ReportError`, and `main()` exits non-zero.

## Out of scope

Live PyRIT execution (deploy-verified; needs a Docker daemon + target); multi-turn orchestration tuning.
