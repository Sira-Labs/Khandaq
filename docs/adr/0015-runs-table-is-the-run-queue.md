# ADR-0015: The worker claims runs from the `runs` table; Procrastinate stays for scheduling

- **Status:** Accepted (2026-10-03)
- **Date:** 2026-10-03
- **Deciders:** implementer, while finishing R1 (spec 012). This narrows ADR-0008, so it is flagged
  for the owner.

## Context

ADR-0008 picked Procrastinate for run execution and campaign scheduling. Spec 012 is the first code
that executes runs asynchronously. Three facts shape it:

- The `runs` row already is the run's state machine: `queued → running → succeeded|failed`, or
  `rejected`. It is audited, and the console reads it.
- The runtime database login has row access only (spec 001, `db_roles`). Procrastinate brings its
  own schema, functions and migration track, each of which would need its own grants and upgrade
  path.
- A queued run must be **re-checked against the scope lock when it starts**, not just when it was
  created. That check reads the same rows the claim locks.

## Decision

- The worker claims work with
  `SELECT … FROM runs WHERE state = 'queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`.
  - In the same transaction it re-evaluates the scope lock, then either rejects the run or marks
    it `running`, and commits before launching anything.
  - Concurrent workers take different runs. A crashed worker's run is failed by the startup
    recovery, after the timeout plus a margin.
- New runs are announced with `NOTIFY khandaq_runs`. The worker `LISTEN`s, and also polls every few
  seconds, so a lost notification only delays a run.
- **Procrastinate remains the plan for campaign scheduling (R2, ADR-0008).** A scheduled campaign
  creates `queued` runs, which this claim loop executes.

## Alternatives considered

| Option | Pros | Cons | Why not now |
|---|---|---|---|
| Procrastinate jobs for runs (ADR-0008 as written) | Retries, scheduling, family-proven | A second state machine beside `runs`; its own schema to provision for the least-privilege login | Two sources of truth for one run |
| **`runs` table claim (chosen)** | One state machine; row grants only; the scope re-check reads what it locks | No built-in retries (a failed run is re-launched by a person, deliberately) | Accepted for runs |

## Consequences

- No new dependency or schema for R1, and backup still covers everything in one datastore.
- Automatic retries are deliberately absent. Re-running an attack against a client system is an
  operator decision, not a queue policy.
