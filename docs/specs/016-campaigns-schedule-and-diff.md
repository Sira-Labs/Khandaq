# Spec 016 — Campaigns: scheduled re-runs and their diff

Sprint 5, story S5-1. Depends on: 002, 005, 012. Packages: `api/` (campaigns, runs, worker,
migration 0008). Decision record: ADR-0017 (scheduler on the run loop).

## Goal

An operator turns a run into a **campaign**: the same adapter, target and parameters, re-run every
N minutes. Every campaign run passes the scope lock and is audited like any other. When a campaign
run succeeds, Khandaq records its **diff** against the campaign's earlier runs: findings that are
`new`, `regressed` (seen before, absent last time, back now), `resolved` (present last time, gone
now) or unchanged. A diff with new or regressed findings is marked `worsened`. This turns a snapshot
into monitoring. (Alerts on a worsened diff are spec 017.)

## User story

As an operator, I schedule a weekly re-run of the prompt-injection suite against the client's
assistant, so that after each release I see what got worse, what got fixed and what came back.

## Interface

- **Tables (migration 0008).**
  - `campaigns`: `id` (`cmp_…`), `engagement_id`, `name`, `adapter`, `target_id`, `params` (jsonb),
    `interval_minutes` (> 0), `enabled`, `next_run_at`, `created_by`, `created_at`, `updated_at`.
    Index `(enabled, next_run_at)`.
  - `runs.campaign_id` (nullable FK), index `(campaign_id, created_at)`.
  - `campaign_diffs`: `id` (`dif_…`), `campaign_id`, `run_id` (unique), `previous_run_id`,
    `baseline` (bool), `new`, `regressed`, `resolved` (jsonb lists of
    `{fingerprint, finding_id, rule_id, severity, title}`), `unchanged_count`, `findings_count`,
    `worsened`, `created_at`. Append-only by trigger, like the ledger.
- **API** (prefix `/api/engagements/{id}`):
  - `POST /campaigns` (owner, operator) `{name, adapter, target_id, params?, interval_minutes,
    start_at?}` → 201 `CampaignOut`.
  - `GET /campaigns` (any member) → `[CampaignOut]`; `GET /campaigns/{cid}` → `CampaignOut`.
  - `PATCH /campaigns/{cid}` (owner, operator) `{enabled?, interval_minutes?}` → `CampaignOut`.
  - `GET /campaigns/{cid}/diffs?limit=` (any member; default 20, max 100, newest first) →
    `[DiffOut]`.
  - `GET /campaigns/{cid}/runs` (any member) → `[RunOut]` (runs gain `campaign_id`).
- **Config.** `KHANDAQ_CAMPAIGN_MIN_INTERVAL_MINUTES` (default 60).
- **Audit.** `campaign.created`, `campaign.rejected` (scope refused at creation), `campaign.updated`
  (before/after), `campaign.run_scheduled` (run id or rejection reason), `campaign.diff` (counts,
  `worsened`).

## Behaviour

1. **Create.** Unknown adapter → 422; target not in this engagement → 404; `interval_minutes` below
   the floor → 422; engagement not `active` → 409. Then the scope lock pre-checks the template with
   the same function as the run path: refused → 422 with the reason, and `campaign.rejected` is
   recorded. Otherwise the campaign is stored with `next_run_at = start_at` (default now; a past
   `start_at` means now), `campaign.created` is recorded, and both commit together.
2. **Schedule (worker, ADR-0017).** Each loop iteration claims due campaigns
   (`enabled AND next_run_at <= now()`, `FOR UPDATE SKIP LOCKED`, at most 20). For each:
   - if a run of the campaign is still `queued` or `running`, no run is created this window;
   - otherwise a run is created through the run path's `queue_run`: scope lock (refused → the run
     is `rejected` and audited), else `queued` with `run.queued`. Builtin adapters are queued too,
     and the worker executes them;
   - `campaign.run_scheduled` is recorded, `next_run_at = now() + interval`, and it all commits
     together.
   A campaign of an engagement that is no longer `active` produces `rejected` runs (the scope
   lock), so the trail shows why nothing ran. Disabling the campaign stops them.
3. **Execute.** Campaign runs are claimed and executed like any other run (claim-time scope
   re-check included).
4. **Diff.** In the transaction that marks a campaign run `succeeded`, after its findings are
   stored: `current` = fingerprints of the findings rows of this run (canonical or not).
   `earlier` = the campaign's earlier `succeeded` runs, and `previous` = the latest of them.
   - No earlier run → a **baseline** diff: `baseline = true`, `findings_count = |current|`, not
     worsened.
   - Otherwise `seen` = fingerprints of all earlier runs. `new = current − seen`,
     `regressed = (current ∩ seen) − previous`, `resolved = previous − current`,
     `unchanged_count = |current ∩ previous|`, `worsened = new ≠ ∅ or regressed ≠ ∅`.
   - Entries carry the canonical finding id of the fingerprint and its rule, severity and title
     (the title is untrusted text, stored as data).
   - `campaign.diff` records the counts. Failed or rejected runs get no diff and do not move the
     baseline.
5. **Update.** `PATCH` changes `enabled` and/or `interval_minutes` (floor applies). Enabling a
   campaign whose `next_run_at` is past schedules it at the next tick. `campaign.updated` records
   before/after. Not allowed on a `closed` engagement (409).
6. **Authz.** Creating and updating need owner or operator (they cause runs against the target);
   reading needs membership. Non-member → 403; another engagement's campaign id → 404.

## Acceptance criteria

- [x] Create validates adapter, target, interval floor, engagement state and scope (refusal audited);
      success audited; `next_run_at` set.
- [x] A due campaign yields one queued run with `campaign_id` and `campaign.run_scheduled`;
      `next_run_at` moves by the interval; a campaign with a run in flight gets none; a disabled one
      gets none; two workers never schedule the same window twice.
- [x] An out-of-scope campaign run (scope narrowed after creation) is `rejected` and audited.
- [x] First successful run → baseline diff; later runs → new / regressed / resolved / unchanged
      computed as specified; worsened set only for new or regressed; failed runs get no diff.
- [x] `PATCH` enable/disable/interval audited with before/after; floor enforced; closed → 409.
- [x] Viewer can read campaigns and diffs, cannot create or update (403); non-member 403; foreign
      campaign 404.
- [x] `campaign_diffs` refuses UPDATE/DELETE (trigger); migration 0008 upgrades and downgrades.

## Test cases

Integration (`api/tests/test_campaigns.py`, Postgres, fake runner returning chosen findings):
create validations + audits; scheduling (due / not due / disabled / in-flight / concurrent
sessions with `SKIP LOCKED`); rejection when scope narrows; diff sequence baseline → new →
resolved → regressed → unchanged; failed run gets no diff; patch + audit; authz; append-only
trigger. `test_migrations`: 0008 up/down. `test_schema`: head revision.

## Out of scope

- Alerts (email/webhook) on a worsened diff: spec 017.
- Cron expressions; per-campaign time windows beyond the rules of engagement.
- Console views for campaigns and diffs: a later console spec.
- Triage-aware diffs (accepted-risk findings excluded from `worsened`).
