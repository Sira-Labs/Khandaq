# Contributing to Khandaq

Thanks for helping build a disciplined command post for authorised AI red teaming. This page
covers the workflow; the design lives in `docs/` and is the source of truth: read
`docs/architecture/03-system-architecture.md`,
`docs/architecture/04-engagement-scope-and-authz.md`,
`docs/architecture/02-domain-model.md` and the ADRs in `docs/adr/` before changing behaviour.

## Ground rules

- **Authorised-use controls are the product.** Never weaken the scope lock, the audit log, or the
  evidence ledger. A change that touches them needs a spec and a reviewer sign-off, and must keep
  the tests that prove them.
- **No offensive content in the repo.** Khandaq *orchestrates* published tools; it does not ship
  novel exploits, payloads, or evasion techniques. Adapters wrap a tool's public interface and
  normalise its output — nothing more. No live targets, credentials, or captured evidence in code,
  fixtures or tests; synthetic only.
- **Design first.** A change that deviates from a documented decision needs a new ADR (copy
  `docs/adr/0000-template.md`), not a silent workaround.
- **Spec first.** Features follow written specs in `docs/specs/` (copy `docs/specs/000-template.md`):
  goal, interface, numbered behaviour, acceptance criteria and test cases, one spec per feature,
  written before the code. `TASKS.md` is the backlog and holds one line per non-obvious decision
  taken while implementing a spec.
- **Findings conform to the canonical schema.** Every finding carries evidence refs, a stable
  fingerprint, a normalised severity and framework mappings. Every adapter has a contract test.
- **No secrets** in code, config, fixtures or tests. Environment variables only; prod refuses
  placeholders.
- Semantic commit messages; scope is the directory or adapter name.

## Development setup

| Part | Toolchain | Commands |
|---|---|---|
| `core/` | Rust 1.88+ | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` |
| `core/khandaq-py/` | maturin | `VIRTUAL_ENV=../../api/.venv ../../api/.venv/bin/maturin develop --release && ../../api/.venv/bin/pytest -q` |
| `api/` | Python 3.12+, uv | `uv sync --extra dev && uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy` |
| `adapters/<tool>/` | Docker | `make build && make contract-test` |
| `web/` | Node 22, pnpm 10 | `pnpm install --frozen-lockfile && pnpm lint && pnpm build` |

`make lint` and `make test` run everything; `make demo` runs a suite against the bundled
intentionally-vulnerable local target and shows the unified report; `make dev-infra` starts
Postgres and an S3-compatible store via docker compose.

## Writing an adapter

An adapter is the only sanctioned way to add a tool. It must:

1. Pin the upstream tool to an **exact** version in its `Dockerfile`.
2. Expose the single contract: given a run request (target + parameters, both already
   scope-checked by the control plane), run the tool and emit findings in the canonical schema to
   the evidence volume. It must not reach any host other than the one the control plane passes it.
3. Carry an `adapter.yaml` manifest: tool name, version, the phases/modules it covers, the
   framework IDs it can emit, and its resource needs.
4. Ship a **contract test** that runs the adapter against a recorded fixture and asserts the output
   still validates against the canonical schema. This is what catches an upstream breaking change.

## Workflow

1. Open or pick an issue. Label it with an `area:` and, if it adds a tool, `type: adapter`.
   Anything that changes a decision gets `needs: design` and an ADR draft. A feature needs a spec
   in `docs/specs/`; the PR links it.
2. Branch from `main`: `feat/<short-topic>`, `fix/<short-topic>`, `docs/<short-topic>`,
   `adapter/<tool>`.
3. Commit in small, logical steps with semantic messages: `feat(core): ...`, `fix(api): ...`,
   `feat(adapter/garak): ...`, `docs: ...`, `test(core): ...`. No debug code, no `WIP` commits on
   the final branch.
4. Open a pull request against `main` and fill in the template. Link the issue with `Closes #n`.
   Keep PRs reviewable: one concern per PR, under ~500 changed lines where possible.
5. CI must be green (`rust core`, `python bindings`, `python api`, `adapters`, `web`). Review
   threads must be resolved before merge. Merge with a merge commit or squash; rebase-merge is off.

## Licence

By contributing you agree your work is licensed under Apache-2.0 (ADR-0002).
