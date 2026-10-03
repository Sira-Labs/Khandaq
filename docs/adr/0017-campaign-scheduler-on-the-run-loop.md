# ADR-0017: Campaigns are scheduled by the worker from a `campaigns` table, not by Procrastinate

- **Status:** Proposed (implementer, spec 016; flagged for the owner)
- **Date:** 2026-10-03
- **Deciders:** implementer. Supersedes the scheduling half of ADR-0008 and the "Procrastinate
  remains the plan for campaign scheduling" line of ADR-0015.

## Context

R2 starts with campaigns: a run that repeats on a schedule and is diffed against what earlier runs
found (domain model, "Campaign & Diff"). ADR-0008 picked Procrastinate for scheduling, and ADR-0015
kept it for that while moving run execution onto the `runs` table. The reasons ADR-0015 gave against
Procrastinate for runs apply to scheduling too:

- The runtime login has row access only (spec 001). Procrastinate needs its own schema, functions
  and migration track, each with grants and an upgrade path.
- A scheduled run must pass the scope lock when it is created and again when it is claimed, and it
  must leave the same audit trail as a run a person starts. That logic already lives in the run path.
- Backups, restore drills and the single datastore stay simpler with one fewer subsystem.

## Decision

- A `campaigns` row holds the run template (adapter, target, params), an interval in minutes, an
  `enabled` flag and `next_run_at`.
- Each worker loop iteration first schedules due campaigns:
  `SELECT … FROM campaigns WHERE enabled AND next_run_at <= now() FOR UPDATE SKIP LOCKED`. For each,
  in one transaction, it creates a run through the same function the API uses: scope lock, then
  `rejected` (audited) or `queued` (audited). It then sets `next_run_at = now() + interval`. Missed
  windows are not replayed.
- A campaign whose previous run is still queued or running is not given another one; its next
  window moves on. Runs never pile up behind a slow tool or a stopped worker.
- The claim loop (ADR-0015) executes campaign runs like any other, including the claim-time scope
  re-check.
- An interval floor (`KHANDAQ_CAMPAIGN_MIN_INTERVAL_MINUTES`, default 60) keeps a campaign from
  hammering a client system. Rules of engagement (rate caps, windows) still apply per run.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Procrastinate periodic tasks (ADR-0008) | Cron syntax, retries, family-proven | Own schema and grants for the least-privilege login; a second scheduler state beside `campaigns` | Same objection as ADR-0015 |
| Cron in the host / CapRover | No code | Outside the audit trail and the scope lock; per-deployment config | Breaks "every run is audited and scope-checked" |
| **`campaigns` table + worker tick (chosen)** | One datastore, row grants only, reuses the run path | Interval only (no cron expressions yet); granularity is the worker poll | Accepted; cron syntax can be added to the same row later |

## Consequences

- No new dependency. Procrastinate is no longer planned. ADR-0008 stays in place for its other
  reasoning (Postgres as the queue) and is superseded on scheduling.
- Scheduling granularity is the worker poll interval (5 s by default); fine for hourly-or-slower
  campaigns.
- Several workers can schedule safely: `SKIP LOCKED` gives each due campaign to one of them.
