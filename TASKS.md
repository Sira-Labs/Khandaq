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
- [ ] S1-2 — spec 002 engagements, scope lock, audit log (auth stubbed)
- [~] S1-3 — repo plumbing: `api/` uv skeleton (done, CI `api` job green), Dockerfiles for api + web,
      `release.yml` publishing images to GHCR (done); `core/` cargo + `web/` pnpm skeletons still to do

### Sprint 2 — data spine
- [ ] S2-1 — spec 003 canonical finding, fingerprint, dedup, severity, mapping (Rust core + wheel)
- [ ] S2-2 — spec 004 hash-chained evidence ledger
- [ ] S2-3 — seed framework mapping tables for R1 adapters

### Sprint 3 — orchestration
- [ ] S3-1 — spec 005 adapter contract + host + run execution (egress-contained)
- [ ] S3-2 — spec 006 garak adapter + contract test
- [ ] S3-3 — bundled intentionally-vulnerable local target

### Sprint 4 — console + adapters + report
- [ ] S4-1 — spec 007 web console (engagements, run launcher, findings inbox)
- [ ] S4-2 — spec 009 (to write) PyRIT adapter
- [ ] S4-3 — spec 010 (to write) promptfoo adapter
- [ ] S4-4 — spec 008 (to write) OIDC (Keycloak) BFF + real roles
- [ ] S4-5 — spec 011 (to write) first management + technical report (Navigator export)

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
- 2026-10-02 — Rust core (PyO3) owns the integrity-critical logic incl. the ledger (ADR-0011/0007);
  Python FastAPI control plane; Procrastinate on Postgres (ADR-0008); adapters isolated per container with
  egress limited to the in-scope target (ADR-0009).
