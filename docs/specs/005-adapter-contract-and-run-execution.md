# Spec 005 — Adapter contract, adapter host, and run execution

Sprint 3, story S3-1. Depends on: 002, 003, 004. Packages: `api/` (adapters, runs, worker),
`adapters/_tooling/`.

## Goal

A defined adapter contract and an adapter host that, for an authorised run, launches the adapter's
container with exactly one in-scope target and constrained egress, collects its canonical findings and
evidence, runs them through the core (validate → fingerprint → dedup → severity → mapping → seal), and
persists the results. The scope lock from spec 002 is wired onto the run-creation path so no run starts
out of scope. (Uses a trivial built-in "echo" adapter for testing; the first real adapter is spec 006.)

## User story

As an operator, I want to start a run and have it execute an isolated tool against only the authorised
target, with its findings normalised and its evidence sealed.

## Interface

- `adapter.yaml` manifest schema: `name`, `version` (exact upstream), `phases`, `frameworks` (IDs it can
  emit), `severity_table`, `resources`, `entrypoint`. Validated by
  `adapters/_tooling/validate_manifests.py` (CI, spec in `.github/workflows/ci.yml`).
- Adapter runtime contract: input = a mounted run-request JSON (target + params, already scope-checked)
  + ephemeral target credential via env; output = canonical findings JSONL + evidence files to the
  mounted evidence volume; exit 0 on success. The adapter must reach **no host** but the one provided.
- API: `POST /api/engagements/{id}/runs` `{suite|adapter, target_id, params}` → scope-checked, enqueued;
  `GET /api/runs/{id}` status; `GET /api/engagements/{id}/findings` inbox.
- A `contract-test` make target per adapter: run against a recorded fixture, assert output validates.

## Behaviour

1. Run creation calls the **same scope-lock function** as spec 002; out-of-scope → run `rejected`,
   audited, nothing launched.
2. The worker launches the adapter container with: the one in-scope target, egress restricted to that
   target's resolved host/port (ADR-0009; on hosts without fine-grained egress, a per-run netns/proxy
   that only forwards there), read-only rootfs where possible, dropped caps, resource limits, and only
   the per-run evidence volume mounted.
3. On completion, raw output + artefacts are written to evidence (encrypted, redacted for display),
   findings are validated/fingerprinted/deduped/severity-mapped/framework-mapped by the core and sealed
   into the ledger, then persisted; run state → `succeeded`/`failed`.
4. A negative control: an adapter that attempts an out-of-scope host cannot connect (test).

## Acceptance criteria

- [ ] Manifest schema + validator; CI fails a manifest without an exact version or a severity table.
- [ ] An authorised run executes the echo adapter, produces canonical findings, seals evidence, persists.
- [ ] An out-of-scope run is rejected on creation (audited), never launched.
- [ ] Egress containment proven: the echo adapter cannot reach a second, out-of-scope host (test).
- [ ] Findings appear in the inbox deduped with framework mappings and sealed evidence refs.

## Test cases

Integration (`api/tests/test_run_execution.py`): authorised run happy path; rejected run; egress
negative test; evidence sealed + ledger verifies. Unit: manifest validator.

## Out of scope

Real tool adapters (spec 006+); campaigns (R2); multi-node runners (R3); the web run launcher
(spec 007).
