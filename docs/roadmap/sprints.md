# Sprint plan — scope sprints with a rolling forecast

*Planned 2026-10-02. A sprint is a unit of scope, not a calendar week: it starts when the previous
sprint's last PR merges, its stories are ordered by priority, and its dates are recorded when they
happen. One branch per sprint (`sprint/NN-topic`), one PR per spec, CodeRabbit review, merge by the
owner, release from `main` deploys to CapRover staging (ADR-0010).*

Definition of done for every story: tests (Rust unit/property, pytest, adapter contract-test, or
vitest), lint clean, docs touched (relevant `docs/`, README, `deploy/README.md`), the
authorised-use invariants preserved with their tests, and — for user-facing stories — a screenshot or
CLI transcript in the PR. Every story gets a spec in `docs/specs/` (copy `000-template.md`) before code.
Priorities: **M** must (sprint fails without it), **S** should, **C** could.

## R1 — the spine

### Sprint 1 — foundation: schema, engagement, scope lock
| Story | Spec | Pri |
|---|---|---|
| S1-1 Persistence schema + migrations + `/api/version` | 001 | M |
| S1-2 Engagements, scope lock, audit log (auth stubbed) | 002 | M |
| S1-3 Repo plumbing: Makefile, uv/cargo/pnpm skeletons, CI green | — | M |

Exit: an engagement can be created, scoped, activated; the scope lock rejects out-of-scope requests with
audited reasons; CI is green across core/api/web stubs.

### Sprint 2 — the data spine: core + ledger
| Story | Spec | Pri |
|---|---|---|
| S2-1 Canonical finding, fingerprint, dedup, severity, mapping (Rust core + wheel) | 003 | M |
| S2-2 Append-only hash-chained evidence ledger | 004 | M |
| S2-3 Seed framework mapping tables for the R1 adapters' rules | 003 | S |

Exit: findings from mixed sources dedup deterministically, map to frameworks, and seal into a verifiable
ledger; the `khandaq-core` CLI can validate/normalise/verify offline.

### Sprint 3 — orchestration: adapters run
| Story | Spec | Pri |
|---|---|---|
| S3-1 Adapter contract + adapter host + run execution (egress-contained) | 005 | M |
| S3-2 garak adapter + contract test | 006 | M |
| S3-3 Bundled intentionally-vulnerable local target | 007 (shared) | S |

Exit: an authorised run launches an isolated garak against the bundled target, normalises + seals its
findings, and the egress negative test passes; out-of-scope runs are refused.

### Sprint 4 — console + more adapters + first report
| Story | Spec | Pri |
|---|---|---|
| S4-1 Web console: engagements, run launcher (scope pre-flight), findings inbox | 007 | M |
| S4-2 PyRIT adapter + contract test | 009 (to write) | M |
| S4-3 promptfoo adapter + contract test | 010 (to write) | S |
| S4-4 OIDC (Keycloak) BFF + real roles, replacing the auth stub | 008 (to write) | M |
| S4-5 First management + technical report (pins ledger root; Navigator export) | 011 (to write) | M |
| S4-6 Adapter execution: egress-contained containers on the worker (closes the R1 exit gap) | 012 | M |
| S4-7 Report re-verification against the pinned ledger root (spec 004 follow-up) | 013 | S |

Exit (**R1 done**): a full engagement — scope → run garak/PyRIT/promptfoo against the bundled target →
deduped findings inbox → sealed evidence → exported report — works end to end, behind real OIDC, deployed
to CapRover staging.

## R2 — coverage (forecast; specs written at sprint start)

| Sprint | Focus | Specs (to write) |
|---|---|---|
| 5 | Campaigns: scheduler, baseline, diff (new/resolved/regressed), alerts | 014–015 |
| 6 | Cisco mcp-scanner adapter (phase 07) + agent target type | 016 |
| 7 | ART adapter (phase 05) + model_artifact/dataset target types | 017–018 |
| 8 | Supply chain: ModelAudit/ModelScan consensus + AI-BOM (phase 08) | 019–020 |
| 9 | Guardrail-regression harness (phase 09) | 021 |

(Forecast numbers shifted by one on 2026-10-03: spec 012 closes R1's execution gap; and by one
again the same day: spec 013 wires the pinned ledger root into report re-verification.)

Exit (**R2 done**): continuous monitoring with regression alerts; coverage across phases 03–09.

## R3 — forensics & platform (forecast)

| Sprint | Focus |
|---|---|
| 10 | IR/forensics: OTel GenAI / Langfuse trace import → incident timelines (phase 10) |
| 11 | Findings → detections; full framework/Navigator exports |
| 12 | SSO/SCIM, API-token hardening, multi-node adapter runners, production promotion |

## Actuals and forecast

Recorded at the end of each sprint: fill in the merge dates and re-forecast the next three from the last
three. The family's measured pace (Thawr, Tabayyun) is roughly one spec per session; Khandaq's Rust core
+ Python API + containerised adapters make sprints 2–3 heavier than a typical Tabayyun sprint, so the
forecast plans conservatively.

| Sprint | Planned | Actual (merge dates) | Notes |
|---|---|---|---|
| 1 | — | _tbd_ | |
| 2 | — | _tbd_ | |
| 3 | — | _tbd_ | |
| 4 | — | _tbd_ | |
