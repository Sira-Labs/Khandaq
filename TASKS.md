# Tasks — backlog and session notes

Backlog, spec status, and one line per non-obvious decision taken while implementing a spec. Specs live
in `docs/specs/`; the sprint plan is `docs/roadmap/sprints.md`.

## Legend
- [ ] todo · [~] in progress · [x] done

## R0 — design (this repository state)

- [x] Product page (`site/index.html`) + brand assets (`docs/assets/`)
- [x] Vision (`docs/VISION.md`) and architecture (`docs/architecture/01–04`)
- [x] Domain model incl. canonical finding; scope/authz/audit design; evidence-ledger design
- [x] Research synthesis (`docs/research/00–04`)
- [x] ADRs 0001–0012
- [x] Specs 001–007 (sprints 1–4)
- [x] Roadmap + sprint plan; CapRover deployment plan + compose/env/captain-definitions
- [x] Repo scaffold: README, CLAUDE.md, CONTRIBUTING, SECURITY, LICENSE, NOTICE, CI, templates, coderabbit

## R1 — the spine (specs to implement)

### Sprint 1 — foundation
- [x] S1-1 — spec 001 persistence schema + migrations + `/api/version` — all 12 tables, Alembic
      migration packaged in the wheel, entrypoint migrates on boot, 8 tests pass against Postgres.
      Decisions: append-only `audit_log` via a DB trigger (portable, single-role); `dedup_of` same-
      engagement via composite FK; enums as CHECKs; SQLAlchemy/psycopg pinned to 2.0.x / 3.2.x.
- [x] S1-2 — spec 002 engagements, scope lock, audit log (auth stubbed) — full lifecycle API,
      server-side scope lock (pure `scope.evaluate` + pre-flight route), append-only audit, per-
      engagement authz. 24 tests pass. Decisions: dev-auth stub refuses in prod (501) pending OIDC
      (spec 008); org admins act as owner; `run.rejected` audit lands with the run path (spec 005).
- [~] S1-3 — repo plumbing: `api/` uv skeleton (done, CI `api` job green), Dockerfiles for api + web,
      `release.yml` publishing images to GHCR (done); `core/` cargo + `web/` pnpm skeletons still to do.
      Fix (2026-10-02): the khandaq-api image failed to build once `api/` gained the `khandaq-core`
      wheel dependency (spec 004) — the build context omitted `core/`, so `uv pip install .` could not
      resolve the `../core/khandaq-py` path source. The build stage now copies `core/` and a Rust
      toolchain (maturin builds the wheel; only the venv ships to the runtime stage); a root
      `.dockerignore` keeps `core/target` and other heavy trees out of the context.

### Sprint 2 — data spine
- [x] S2-1 — spec 003 canonical finding, fingerprint, dedup, severity, mapping (Rust core + wheel) —
      `core/` workspace (khandaq-core + khandaq-cli) + PyO3 wheel `khandaq_core`; 7 Rust tests + 5
      Python binding tests pass; clippy/fmt clean; CI `core` + `bindings` jobs online. Decisions:
      serde typed model mirrors finding.schema.json; fingerprint identity = mapping-ids+target+location
      (rule_id fallback); JSON-in/out bindings; `dedup_of` id-linking lands with spec 005.
- [x] S2-2 — spec 004 hash-chained evidence ledger — Rust `ledger` module (append/verify/root) + wheel
      bindings + API ledger service & read/verify endpoints; the api now depends on the `khandaq_core`
      wheel (api CI job gains a Rust toolchain). 5 Rust + 1 binding + 2 API ledger tests pass.
      **Follow-up:** Sigstore signing of the ledger root is deferred (offline chain works today).
- [ ] S2-3 — seed framework mapping tables for R1 adapters

### Sprint 3 — orchestration
- [x] S3-1 — spec 005 adapter contract + host + run execution — manifest model + CI validator; adapter
      registry + runners (in-process `echo`, `DockerRunner` command build); run service wires the scope
      lock onto the run path (rejected+audited), executes, seals evidence, normalises+dedups via the
      core, persists canonical findings; runs + findings-inbox endpoints. 33 api tests pass.
      **Follow-ups:** async execution on the Procrastinate worker; evidence bytes upload to the object
      store (hash+metadata sealed today); real Docker execution lands with spec 006.
- [x] S3-3 — bundled vulnerable local target: partially covered by the in-process `echo` adapter for the
      demo/tests; a networked vulnerable target ships with the web demo (spec 007).
- [x] S3-2 — spec 006 garak adapter + contract test — `adapters/garak/` (Dockerfile pinned to
      garak 0.17.0, `wrap.py` report parser, `adapter.yaml`, Makefile); contract test parses a recorded
      garak fixture → 3 schema-valid, mapped findings; CI adapters job runs contract tests; release.yml
      publishes `khandaq-adapter-garak`. **Follow-up:** Docker execution + disk-manifest registry
      wiring (deploy-verified; needs a daemon).
- [ ] S3-3 — bundled intentionally-vulnerable local target

### Sprint 4 — console + adapters + report
- [x] S4-1 — spec 007 web console — Vite + React 19 + TanStack Query + Tailwind v4 SPA (engagements
      list/create, engagement detail with scope-pre-flight run launcher + ledger status, findings inbox
      with severity filter + drawer). API read endpoints added (list engagements/targets/scope/members).
      web Dockerfile (multi-stage) + CI `web` job. 3 web tests (XSS-escaping, scope pre-flight) + 35 api
      tests pass. Bundled vulnerable target at `deploy/targets/vulnerable-llm/`. Deviations: minimal
      in-app router (TanStack Router later); echo launcher in-browser (garak via Docker in deploy);
      UI role-hiding deferred (enforced API-side).
- [x] S4-2 — spec 009 PyRIT adapter — `adapters/pyrit/` (Dockerfile pinned to pyrit 1.1.0, wrap.py
      parser for scored conversations, adapter.yaml, fixture, contract test); successful attacks →
      high findings. Adapter contract tests now run with `--import-mode=importlib`; release.yml
      publishes `khandaq-adapter-pyrit`. 5 adapter contract tests pass.
- [x] S4-3 — spec 010 promptfoo adapter — `adapters/promptfoo/` (Dockerfile pinned to promptfoo
      0.118.0, wrap.py parser for promptfoo JSON results, adapter.yaml, fixture, contract test); failed
      red-team tests → mapped findings by plugin family. release.yml publishes
      `khandaq-adapter-promptfoo`. 8 adapter contract tests pass.
- [x] S4-4 — spec 008 OIDC (Keycloak) BFF + real roles — auth package (`auth/oidc.py` injectable
      OIDC client, `auth/signing.py` HMAC login-state cookie, `auth/service.py` sessions + API
      tokens), `sessions` table (migration 0002), `routers/auth.py` (`/login` `/callback` `/logout`
      `/me` `/tokens`). `current_user` now resolves Bearer API token → session cookie → dev stub
      (non-prod); CSRF header enforced on session-authenticated mutations; prod fails closed without
      OIDC settings and no longer returns 501. 10 new tests (an injected fake IdP drives the full
      callback→session path) + test_settings; 48 api tests pass, ruff/mypy clean. Decisions:
      migration 0002 guards `CREATE TABLE sessions` on existence because 0001 is a `create_all`
      baseline that now also makes the table on a fresh DB; API tokens stored sha256-only, plaintext
      shown once; token-authenticated actions attributed via an audit contextvar (`actor_token_id`);
      live Keycloak end-to-end is deploy-verified (realm export at `deploy/keycloak/`).
- [x] S4-5 — spec 011 first report — `reports.py` builds a management summary (counts by severity +
      framework, evidence-ledger root + verify) and a technical finding list; endpoints `GET /report`
      (JSON), `/report.html` (escaped HTML), `/report/navigator` (ATLAS Navigator via the core). 38 api
      tests pass.

## Owner / external dependencies (not software; do not block sprints on these)

- [ ] Confirm the public name/domain: GitHub `Sira-Labs/Khandaq` is taken (good); check PyPI name and a
      domain if one is wanted.
- [ ] Production CapRover server (Germany) ordered/confirmed (ADR-0010).
- [ ] Keycloak `khandaq` realm + `khandaq-api` client (before the first real user). Realm export ready
      at `deploy/keycloak/khandaq-realm.json` (render + import, then set the client/broker secrets).
- [ ] Evidence-encryption key / KMS story and its backup (ADR-0006); **losing it makes evidence unreadable**.
- [ ] Backup location for Postgres + evidence bucket; first timed restore drill (ADR-0010).
- [ ] GitHub environments (`staging`, `production`) + secrets + `v*` tag ruleset for promote.yml.
- [ ] Decide adapter-execution shape per server: A (docker socket) for staging/self-host, B (dedicated
      runner host) for production (ADR-0009).
- [ ] Any pilot engagement runs only against systems with signed authorisation (SECURITY.md).

## Decisions log (non-obvious choices)

- 2026-10-02 — R0 foundation laid: orchestrate-not-reimplement (ADR-0001) is the spine of everything;
  the scope lock, audit log and hash-chained evidence ledger are treated as the product, with CODEOWNERS
  and CodeRabbit path-instructions guarding them.
- 2026-10-02 — Canonical finding is a SARIF superset (ADR-0003) so results interoperate; dedup by stable
  fingerprint; severity normalised to five levels (ADR-0004); framework mappings are versioned data with
  both OWASP LLM 2025 and 2026 kept in parallel (ADR-0012).
- 2026-10-02 — Bootable control-plane image shipped so CapRover deploys stop failing at `khandaq-api`
  (no image existed at R0). `khandaq-api` boots with `/api/health` + `/api/version`, fail-closed in
  prod (settings.validate_runtime); `khandaq-web` serves the landing and proxies `/api`; both built and
  pushed to GHCR by `release.yml` on push to main. Domain features still land spec by spec.
- 2026-10-02 — Scope lock hardening (code review): on the old code 8 of 10 crafted targets/requests
  were allowed (e.g. `host` allowed while `base_url` pointed at a denied host; trailing-dot host
  dodging a `*.` deny; missing model under a model restriction; params overriding the model; an
  undeclared rate under a cap; a midnight window opening the previous night; a mistyped zone read as
  UTC) and a string rate crashed with a 500 and no audit record. Targets are now canonicalised and
  must be unambiguous; scope documents are validated on write; evaluation never raises. Spec 002 §6.
- 2026-10-02 — Full code review (4 parallel reviewers, findings verified before fixing). Auth: the
  realm brokers any Google/GitHub account and every login became an org `member` able to create
  engagements and start runs → sign-in now needs a verified email on `KHANDAQ_ALLOWED_EMAILS` (or
  `KHANDAQ_ADMIN_EMAIL`), mirroring Sahifa's `SAHIFA_ALLOWED_EMAILS`; `KHANDAQ_ENV` is strict
  (typos such as `production` would have enabled the dev stub); prod reads only the `__Host-` cookie;
  token attribution moved off a `ContextVar` that never crossed FastAPI's threadpool.
- 2026-10-02 — Adapters fail closed (code review, checked against the pinned upstream packages):
  garak 0.17 writes `total_evaluated`/`fails`, not `total`, so every real garak result was dropped
  and the run read as clean (the recorded fixture was hand-written in the wrong shape; re-recorded in
  the 0.17 shape). PyRIT is now read by `AttackResult.outcome`, with its string `score_value`
  ("0.9") understood; promptfoo errors (`failureReason` 2) are no longer findings. Each parser
  refuses a truncated, incomplete (no garak `completion` record, no wrapper completion count, stats
  mismatch), empty or all-errored report, and `main()` exits non-zero without writing
  `findings.jsonl`, so a run that produced nothing trustworthy fails instead of reporting zero
  findings. Invoking the tools inside the sandbox is still the spec 005/006 Docker follow-up.
- 2026-10-02 — Run-path integrity (code review): the run row and `run.started` were only flushed
  before the adapter executed, so a DB error while saving results (e.g. two concurrent runs racing
  for the same ledger `seq`) rolled back every trace of a run that had already reached the target.
  Now committed first, failures recorded in a fresh transaction, and appends serialised with a
  per-engagement advisory lock. Dedup now spans runs (partial unique index; `dedup_of` links);
  `evidence`/`ledger_entries` are append-only by trigger and TRUNCATE is blocked on all three.
  **Open decision for the owner:** the ledger seals only the adapter-reported sha256, so an evidence
  row's `object_key`/`run_id`/`kind` are outside the chain (triggers stop app-level edits, not a DBA).
  Binding a canonical evidence record into `evidence_hash` changes ADR-0007's formula and would
  invalidate existing staging chains — proposed, not done; needs an ADR.
- 2026-10-02 — Rust core hardening (code review): validation dropped every field the typed model
  did not name, which broke the SARIF superset, and it accepted `HIGH` and non-object locations,
  unlike the published schema. Both are fixed. Dedup is now independent of input order, keeps
  every tool's native severity (`x-khandaq.sources`) and unions `also_found_by`. The Navigator
  counts per finding. The ledger refuses malformed hashes and seq overflow, and gains
  `verify_pinned` to detect truncation. `khandaq-py` was outside the workspace, so CI never ran
  fmt/clippy/audit on it; the job now does. pyo3 is bumped from 0.22 to 0.26 (RUSTSEC-2025-0020;
  the affected API is unused here), which also clears pyo3 0.22's clippy false positive.
  **Open decision for the owner:** ADR-0013 (Proposed) would take framework mappings out of the
  fingerprint, because every mapping edit currently re-fingerprints the same issue and defeats
  cross-run dedup.
- 2026-10-02 — Staging naming + worker boot fix: staging is deployed as `khandaq-stg-<role>` on
  `https://khandaq-stg.siralabs.org` (the one-click's `<app>-<role>` shape); the docs said
  `khandaq-<role>-stg` and showed only production values. `deploy/caprover.md` now has a
  per-environment values table — the public origin must be identical on the web app's domain,
  `KHANDAQ_PUBLIC_URL` and the realm render, and the OIDC client id stays `khandaq-api`. Also fixed a
  spec-008 regression: `validate_runtime()` required OIDC settings for every prod role, so the
  worker (deployed without the client secret) would refuse to start; OIDC is now required for the
  `api` role only.
- 2026-10-02 — Keycloak realm import fix: the docs told operators to use **Partial import**, which
  skips `authenticationFlows`/`authenticatorConfig` and the `browserFlow`/`firstBrokerLoginFlow`
  bindings this realm relies on, so the realm came up broken ("could not be created"). Docs now say
  **Create realm → Resource file** (full import), matching Sahifa's working procedure. Also brought the
  realm in line with Sahifa (SSO cookie tried before the IdP redirect; `loginHint` on Google) and
  ported Sahifa's hardened `render.py`. The realm JSON was otherwise identical to Tabayyun's.
- 2026-10-02 — Real authentication landed (spec 008 / ADR-0005): OIDC Authorization-Code + PKCE
  against Keycloak, a backend-for-frontend `__Host-` session cookie (no tokens in the browser), CSRF
  on state-changing requests, and revocable, audited API tokens for automation. The dev header stub
  is now non-prod only; prod fails closed without OIDC and returns 401 (not 501) when unauthenticated.
  This completes the R1 spine: authenticated users → engagement → scope-locked run → deduped/mapped
  findings → sealed/verifiable evidence → framework-mapped report. All R1 specs (001–011) implemented.
- 2026-10-02 — Rust core (PyO3) owns the integrity-critical logic incl. the ledger (ADR-0011/0007);
  Python FastAPI control plane; Procrastinate on Postgres (ADR-0008); adapters isolated per container with
  egress limited to the in-scope target (ADR-0009).
- 2026-10-03 — Fingerprint v2 (ADR-0013 accepted by the owner): framework mappings are no longer
  identity. The fingerprint is `{v: 2, weakness, target, location}`, where `weakness` is the rule id
  unless a versioned equivalence table (`core/khandaq-core/mappings/equivalence.json`, shipped
  empty because no two R1 adapters share a location vocabulary) names a shared one. Schema id
  `khandaq.finding/2`; `/1` still validates. Migration `0004_fingerprint_v2` re-fingerprints stored
  findings, rebuilds `dedup_of`, recomputes a changed group's evidence from each member's own run
  (evidence rows carry `run_id`) and its tools from `source`/`sources`, carries triage over a merge,
  and audits `findings.refingerprinted` per engagement. Downgrade uses a Python copy of the v1
  recipe pinned against the old core's output. The echo adapter's duplicate pair now shares a rule.
