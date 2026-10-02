# Spec 002 — Engagements, the scope lock, and the audit log

Sprint 1, story S1-2. Depends on: 001. Packages: `api/` (engagements, scope, audit, authz).

## Goal

An operator can create an engagement, declare targets, scope and rules of engagement, and activate it.
Once active, a server-side **scope lock** evaluates every prospective run against the scope + RoE and
**rejects out-of-scope requests before anything is enqueued**, writing an audit entry either way. This
is the control that makes the rest of the product safe; it is enforced in the API and covered by
negative tests. (Auth is stubbed to a fixed admin user here; real OIDC is spec 008.)

## User story

As an offensive AI security consultant, I want an engagement with a locked scope so that every run is
provably inside the boundary I am authorised to test, with an audit trail.

## Interface

Routes (all require an authenticated user; `authorize()` checks the engagement role):

- `POST /api/engagements` → create (state `draft`); caller becomes `owner`.
- `POST /api/engagements/{id}/targets` → add a target (draft only).
- `PUT /api/engagements/{id}/scope` → set allow/deny/RoE (draft only).
- `POST /api/engagements/{id}/activate` → requires scope + ≥1 target + `authorisation_ref`; locks scope.
- `POST /api/engagements/{id}/scope-check` → body `{target_id, params}` → `{allowed: bool, reason}`
  (the scope lock, exposed for the console/CLI to pre-flight; the authoritative call is also made
  internally on run creation in spec 005).
- `POST /api/engagements/{id}/close` → state `closed` (owner).
- `GET /api/engagements/{id}/audit` → audit entries (owner/admin).

Scope document shape and the lock algorithm: `docs/architecture/04-engagement-scope-and-authz.md`.

## Behaviour

1. Create/targets/scope are allowed only in `draft`; mutating an `active` engagement's scope requires
   the owner and is an audited change that bumps `scopes.version` and records before/after.
2. `activate` fails (422) without a scope, at least one target, and an `authorisation_ref`; on success
   sets `locked=true`, state `active`, and writes `engagement.activated` to the audit log.
3. **Scope lock** (`scope-check` and the internal check): resolve the target → it MUST match an `allow`
   rule for its type → MUST NOT match any `deny` rule → current time MUST be within an RoE window →
   requested rate MUST be ≤ RoE limit → suite MUST NOT use a prohibited technique. Any failure →
   `allowed=false` with a specific `reason`; a rejection on the run path sets run state `rejected` and
   writes `run.rejected` with the reason. **Default deny:** no matching allow rule → rejected.
4. Every privileged action writes an audit entry (actor, action, engagement, detail, at).
5. Cross-engagement access is refused: a user without a role on the engagement gets 403.

## Acceptance criteria

- [x] Full lifecycle `draft → active → closed` via the API, with the activation preconditions enforced.
- [x] Scope lock allows an in-scope target and **rejects** each of: unknown host, denied host, wrong
      model id, out-of-window time, over-rate, prohibited technique — each with a distinct reason
      (exhaustive table in `tests/test_scope_eval.py`).
- [x] Default deny: a target matching no allow rule is rejected.
- [x] Changing an active engagement's scope is owner-only, audited, and bumps the version.
- [x] Every privileged action (create, activate, scope change, close) appears in the audit log; audit
      rows cannot be updated/deleted (from spec 001). (Run rejection audit lands with the run path, spec 005.)
- [x] A user with no role on an engagement is refused (403).

> Notes (recorded per CLAUDE.md): auth is a dev stub (`X-Khandaq-Dev-User` header) that **refuses to
> authenticate in prod** (501) until OIDC lands (spec 008), so no insecure prod default ships. Org
> admins are treated as engagement `owner`. The `scope-check` route is the pre-flight; spec 005 wires
> the same `scope.evaluate` onto the run-creation path and adds the `run.rejected` audit entry.

## Test cases

Integration (`api/tests/test_scope_lock.py`): a table-driven suite of in-scope and out-of-scope cases,
each asserting `allowed` and `reason`; activation precondition failures; audit entries written;
cross-engagement 403. Unit (`api/tests/test_scope_eval.py`): the pure scope-evaluation function.

## Out of scope

Real OIDC/roles (spec 008); starting adapters (spec 005); per-run egress enforcement (spec 005 +
deploy). The `scope-check` route here evaluates; the run path wires the same function in spec 005.
