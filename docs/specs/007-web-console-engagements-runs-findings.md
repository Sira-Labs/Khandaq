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
5. **Sign-in** (added 2026-10-02; this console predated spec 008 and did not work against it in
   production — every read was 401 and every write 403):
   - On load the console calls `GET /api/auth/me`. With no session it shows a **Sign in** button to
     `/api/auth/login?next=<current path>`. It never redirects on its own, because an IdP session
     for a refused account would otherwise loop. `/?signin=denied` (and a 403 from `/me`) shows a
     "no access" notice with "Sign in with another account".
   - Every POST/PUT/PATCH/DELETE carries `X-Khandaq-CSRF` with the session's token from `/me`.
   - Signed in, the header shows the user and **Sign out** (`POST /api/auth/logout`). The dev
     identity box appears only when the API reports `auth: "dev"`, and the dev header is sent only
     then.
   - The launcher sends the same `params` to the pre-flight and the run, with an optional
     `rate_per_minute` (required when the RoE caps the rate, spec 002 §6). A failed pre-flight shows
     its reason instead of leaving "Run" disabled; run and query errors are shown.

## Acceptance criteria

- [x] Dev sign-in (header), list engagements, open one, launch an adapter against a target, and see
      deduped findings with mappings and evidence. (Launcher uses `echo` in-browser; garak runs via the
      Docker runner in deploy.)
- [x] Scope pre-flight blocks an out-of-scope launch with the reason (Run stays disabled; tested).
- [x] Inbox shows deduped canonical findings with a severity filter and a finding drawer (mappings +
      evidence count); `also_found_by` shows contributing tools.
- [~] `make demo` / bundled vulnerable target: the target ships at `deploy/targets/vulnerable-llm/`
      (FastAPI, intentionally weak). End-to-end demo runs in deploy (needs Docker); the echo pipeline
      covers CI.
- [x] Untrusted finding text is escaped (React escapes; XSS test asserts a malicious title renders as
      text and injects no element). Role gating is enforced **API-side** (operator/owner to run);
      UI-side hiding of controls for viewers is a follow-up.

> Notes (per CLAUDE.md): R1 uses a **minimal in-app router** (TanStack Router adoption deferred) and
> dev-auth via the `X-Khandaq-Dev-User` header (OIDC is spec 008). API read endpoints added to back the
> console: list engagements, targets, scope, members. Lint is `tsc --noEmit` for R1 (ESLint later).

## Test cases

Web (`web/src/__tests__/`): engagements list, launcher scope pre-flight, inbox filters/grouping, finding
drawer escaping. e2e (`make demo` / Playwright): sign-in → run garak vs bundled target → inbox → drawer.

## Out of scope

Real OIDC (spec 008); campaign dashboard and diffs (R2); report export polish (R1 report is spec 011);
PyRIT/promptfoo adapters (specs 009–010).
