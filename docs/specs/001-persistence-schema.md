# Spec 001 — Persistence schema and migrations

Sprint 1, story S1-1. Depends on: none. Packages: `api/` (db, models, migrations).

## Goal

A PostgreSQL schema and Alembic migrations exist for the core domain: users and roles, engagements,
targets, scope, runs, findings, evidence references, and the audit log. The API can connect, run
migrations on start, and report the schema revision at `GET /api/version`. No business logic yet —
this spec is the tables the later specs build on, with the integrity constraints that make the
authorised-use controls enforceable.

## User story

As a platform admin, I want a migrated database so that engagements, findings and the audit trail have
a durable, constrained home.

## Interface

Tables (columns abbreviated; all have `created_at timestamptz`):

- `users` (id `usr_…`, email unique, display_name, org_role `admin|member|read_only`, disabled bool)
- `api_tokens` (id `tok_…`, user_id fk, name, hash, last_used_at, revoked_at)
- `engagements` (id `eng_…`, name, client, owner_user_id fk, state `draft|active|closed`,
  authorisation_ref, activated_at, closed_at)
- `engagement_members` (engagement_id fk, user_id fk, role `owner|operator|analyst|viewer`,
  PK(engagement_id,user_id))
- `targets` (id `tgt_…`, engagement_id fk, type `llm_endpoint|agent|mcp_server|model_artifact|dataset`,
  spec jsonb, credential_ref nullable)
- `scopes` (engagement_id fk unique, version int, allow jsonb, deny jsonb, roe jsonb, locked bool)
- `suites` (id `ste_…`, name, version, definition jsonb) — seed data, global
- `runs` (id `run_…`, engagement_id fk, suite_id fk nullable, adapter, adapter_version, target_id fk,
  params jsonb, state `queued|running|succeeded|failed|rejected`, reject_reason, started_at, ended_at)
- `findings` (id `fnd_…`, engagement_id fk, run_id fk, fingerprint, canonical bool, dedup_of fk
  nullable, rule_id, title, severity, confidence, body jsonb /* full canonical finding */,
  status `open|triaged|accepted_risk|fixed|false_positive`)
- `evidence` (id `ev_…`, engagement_id fk, run_id fk, kind, object_key, sha256, bytes, redacted bool)
- `ledger_entries` (id `led_…`, engagement_id fk, seq int, evidence_id fk, entry_hash, prev_hash,
  UNIQUE(engagement_id,seq))
- `audit_log` (id `aud_…`, actor_user_id, actor_token_id nullable, action, engagement_id nullable,
  detail jsonb, at timestamptz) — append-only

Config keys: `KHANDAQ_DATABASE_URL`, `KHANDAQ_MIGRATION_DATABASE_URL`, `KHANDAQ_ENV`.

## Behaviour

1. `uv run khandaq-db upgrade head` applies migrations; the API runs this on start before serving.
2. `GET /api/version` returns `{ "schema_revision": "<rev>", "app": "<version>" }`.
3. Constraints enforce invariants other specs rely on: `findings.dedup_of` references a finding in the
   same engagement (composite FK on `(engagement_id, id)`); `ledger_entries` is unique and ordered per
   engagement; `audit_log` is **append-only, enforced by a database trigger** that rejects UPDATE and
   DELETE; `engagement_members.role` and all enum columns are constrained by CHECKs.

   > Deviation from the draft (recorded per CLAUDE.md): append-only is enforced by a trigger rather than
   > by withholding UPDATE/DELETE from a separate app DB role. The trigger holds regardless of the login
   > used, so it works with the single-role one-click/compose deployments and in CI; a restricted app
   > role remains an optional prod hardening (deploy/caprover.md). Enums use CHECK constraints rather
   > than native PG enum types to keep migrations simple.
   >
   > Update 2026-10-02 (code review): a trigger does not stop the table's **owner**, who can disable
   > it, and the API connected as the owner. Both layers now apply: when `KHANDAQ_DATABASE_URL` names
   > a different login than the migration owner, `khandaq.db_roles` creates/restricts it on every boot
   > (row access only; INSERT/SELECT on `audit_log`, `evidence`, `ledger_entries`; read-only
   > `alembic_version`; owns nothing), and the entrypoint drops the owner URL before serving. The
   > deploy templates use a separate `khandaq_app` login. Single-login installs keep the trigger.
   > Its *effective* rights are checked after provisioning: no CREATE (schema or database), no
   > TEMPORARY, and no UPDATE/DELETE/TRUNCATE/TRIGGER on the append-only tables, even when the
   > right comes through `PUBLIC`. If one cannot be removed, boot fails. An existing login's
   > password and LOGIN are never rewritten, so a restart cannot undo an administrator's rotation
   > or `NOLOGIN`. If the URL no longer authenticates, boot fails with instructions.
4. With `KHANDAQ_ENV=prod`, the app refuses to start on a placeholder DB URL.

## Acceptance criteria

- [x] Migrations create every table above with the stated constraints and enums.
- [x] API runs migrations on start (entrypoint `khandaq-db upgrade head`, with retry) and
      `GET /api/version` reports the revision.
- [x] `audit_log` rejects UPDATE and DELETE (append-only trigger), while INSERT works (tested).
- [x] `findings.dedup_of` cross-engagement reference is rejected by the composite FK (tested).
- [x] `ledger_entries(engagement_id, seq)` uniqueness is enforced (tested).

## Test cases

Integration (`api/tests/test_schema.py`): migrate up/down clean; version endpoint; append-only audit
(UPDATE/DELETE raises); dedup_of same-engagement constraint; ledger seq uniqueness.

## Out of scope

Business logic for any table (later specs); RLS (revisit in R3); the full finding `body` schema
(spec 003 defines it; here it is `jsonb`).
