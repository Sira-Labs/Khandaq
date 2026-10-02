# Khandaq — working notes for Claude Code

Self-hostable platform for **authorised** AI red-team engagements. It orchestrates upstream
open-source tools, unifies their findings, keeps a signed chain of evidence, and monitors for
regression. Read `docs/` before changing design:
`docs/architecture/03-system-architecture.md`, `docs/architecture/04-engagement-scope-and-authz.md`,
`docs/adr/` (decisions — add a new ADR rather than silently deviating), and the one spec the
session names.

## Non-negotiable: authorised use, enforced in code

Khandaq exists to test AI systems **you are authorised to test**. This is enforced, not assumed:

- Every tool run belongs to an **engagement** with declared in-scope targets and rules of
  engagement. The **scope lock** refuses any target outside it; this check is server-side and
  has unit tests. Never add a path that lets a run reach an out-of-scope target.
- Every privileged action writes to an **append-only audit log**. Never add an action that
  mutates engagement state without an audit entry.
- Khandaq **orchestrates** published tools; it does not implement novel attacks. Do not add
  offensive payloads, exploit code, or evasion techniques to this repository. Adapters wrap a
  tool's public interface and normalise its output — nothing more.
- No live credentials, targets, or captured evidence in the repo, fixtures or tests. Synthetic
  only.

If a change would weaken the scope lock, the audit trail, or the evidence integrity, stop and
raise it — those are the product.

## Session protocol (spec-driven, as in Thawr and Tabayyun)

1. One spec per session. The prompt names it (`Implement docs/specs/NNN-name.md. Plan first.`).
   Read this file, `docs/architecture/03-system-architecture.md`, the engagement/scope/authz
   doc, and that one spec plus the specs it references; do not read all specs.
2. Present the plan, wait for approval, then implement. Deviating from a spec, an ADR or a fixed
   architecture decision needs a question first, or a new ADR.
3. `make lint` and `make test` (or the relevant subset) before every commit; semantic commits,
   one logical change each; a spec may take several commits.
4. When the spec's acceptance criteria are met, tick them in the spec, mark it done in
   `TASKS.md`, and add one line per non-obvious decision under its entry.
5. Do not start the next spec in the same session. Do not refactor code the spec does not touch.
6. A story in `docs/roadmap/sprints.md` gets its spec (copy `docs/specs/000-template.md`) before
   any code; a spec that turns out wrong is edited in the same PR, with the reason.

## Layout
- `core/` Rust workspace: `khandaq-core` (findings model, canonicalisation, fingerprint/dedup,
  severity, framework mapping, hash-chained ledger), `khandaq-cli` (`khandaq` binary),
  `khandaq-py` (PyO3 wheel `khandaq_core`).
- `api/` Python 3.12+ FastAPI (uv). `src/khandaq/` (auth, authz, engagements, scope, runs,
  findings, campaigns, reports, worker, adapter host), tests in `tests/`.
- `adapters/` one directory per tool (`garak/`, `pyrit/`, `promptfoo/`, …): a thin wrapper plus a
  `Dockerfile` pinned to an exact upstream version and an `adapter.yaml` manifest.
- `web/` Vite + React 19 + TanStack + Tailwind SPA (pnpm).
- `deploy/` compose bundle, Caddyfile, CapRover guide and captain-definitions; `docs/` design.

## Commands
- `make lint` / `make test` run everything. `make demo` runs a suite against the bundled
  **intentionally-vulnerable local target** (never a third party) and shows the unified report.
- Rust: `cd core && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
- Python: `cd api && uv sync --extra dev && uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy`
- Bindings: `cd core/khandaq-py && VIRTUAL_ENV=../../api/.venv ../../api/.venv/bin/maturin develop --release && ../../api/.venv/bin/pytest -q`
- Web: `cd web && pnpm install --frozen-lockfile && pnpm lint && pnpm build`
- Adapters: each has `make build` (image) and `make contract-test` (runs the adapter against a
  recorded fixture and checks it still emits the canonical findings schema).

## Conventions
- Findings conform to the canonical schema (`docs/architecture/02-domain-model.md`), a SARIF
  superset. Every finding carries evidence refs, a stable fingerprint, a normalised severity and
  framework mappings (ATLAS, OWASP LLM 2025 + 2026, OWASP Agentic, NIST AI RMF).
- Adapters are **thin**: wrap the tool's public CLI/SDK, pin the exact version, translate output
  to the canonical schema, emit nothing else. Every adapter has a contract test against a recorded
  fixture, so an upstream change that breaks the mapping fails CI.
- Evidence is append-only and hash-chained; never mutate or delete a sealed bundle (ADR-0007).
- No secrets in code or config; env vars only; prod refuses placeholders.
- Timestamps are RFC 3339 UTC in the API, `i64` ns since epoch in the core.
- Semantic commit messages (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `test:`); scope is
  the directory or adapter name.
- Diagrams are Mermaid in Markdown (GitHub renders them), not ASCII art; check a new one renders.
- Licence is Apache-2.0 (ADR-0002). Workflow, PR checklist and branch rules: `CONTRIBUTING.md`.
- Backlog and session notes: `TASKS.md`. Specs: `docs/specs/`. Sprint plan: `docs/roadmap/sprints.md`.
