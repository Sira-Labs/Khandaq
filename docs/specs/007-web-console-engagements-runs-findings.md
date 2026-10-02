# Spec 007 — Web console: engagements, run launcher, findings inbox

Sprint 4, story S4-1. Depends on: 002, 005, 006. Packages: `web/`, `api/` (read endpoints).

## Goal

A web console where an operator signs in, sees their engagements, opens one to view its scope, members
and runs, launches a suite/adapter against an in-scope target (with a scope pre-flight), and triages the
unified findings inbox — grouped, deduped, filterable by severity, framework and phase, each finding
showing its evidence refs and mappings. Plus a bundled intentionally-vulnerable local target so the
console can be demoed without any third-party system.

## User story

As an in-house AI red teamer, I want a console to run suites and triage deduped findings so that I do not
assemble results by hand.

## Interface

Routes (React + TanStack): `/` engagements list; `/eng/:id` detail (scope, members, runs, campaigns tab
placeholder); `/eng/:id/run` launcher (adapter/suite + target picker, scope pre-flight banner);
`/eng/:id/findings` inbox (group-by fingerprint; filters: severity, framework, phase, status;
finding drawer with evidence + mappings); `/eng/:id/audit` (owner/admin). BFF cookie session (OIDC is
spec 008; here a dev login stub). API read endpoints back each view.

Bundled target: `deploy/targets/vulnerable-llm/` — a tiny, deliberately weak local LLM-style endpoint
(no real provider; canned weak behaviour) used by `make demo` and the e2e test. **Never a third party.**

## Behaviour

1. The launcher calls `scope-check` before enabling "Run"; an out-of-scope selection is shown as refused
   with the reason; it cannot be submitted.
2. The inbox groups duplicates under one canonical finding showing all contributing tools; filters are
   server-side; the drawer renders evidence refs (redacted where applicable) and every framework mapping.
3. All finding/evidence text is treated as untrusted and escaped on render (it contains model/attacker
   output); no raw HTML injection.
4. Roles gate the UI: a `viewer` cannot launch runs; the audit tab is owner/admin only.

## Acceptance criteria

- [ ] Sign in (dev stub), list engagements, open one, launch the garak suite against the bundled target,
      and see deduped findings with mappings and evidence.
- [ ] Scope pre-flight blocks an out-of-scope launch with the reason.
- [ ] Inbox grouping/dedup, filters (severity/framework/phase/status), and the finding drawer work.
- [ ] `make demo` runs a suite against the bundled vulnerable target and the report renders.
- [ ] Untrusted finding text is escaped (XSS test); role gating enforced in UI and API.

## Test cases

Web (`web/src/__tests__/`): engagements list, launcher scope pre-flight, inbox filters/grouping, finding
drawer escaping. e2e (`make demo` / Playwright): sign-in → run garak vs bundled target → inbox → drawer.

## Out of scope

Real OIDC (spec 008); campaign dashboard and diffs (R2); report export polish (R1 report is spec 011);
PyRIT/promptfoo adapters (specs 009–010).
