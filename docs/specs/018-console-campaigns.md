# Spec 018 — Console: campaigns, their runs, diffs and alerts

Sprint 5, story S5-3. Depends on: 015, 016, 017. Packages: `web/`.

## Goal

The console shows the campaigns of specs 016 and 017. On the engagement page you can list, create
and pause campaigns. Each campaign has a page with its runs, its diffs (baseline, new, regressed,
resolved, unchanged, worsened) and its alerts. There are no API changes.

## User story

As an operator, I set up a weekly campaign from the engagement page. After each run I open it and
see at a glance whether anything got worse, which rules are new or came back, and whether the team
was alerted.

## Interface

- **Campaigns panel** (engagement page): rows with name, adapter, "every N min", next run, and an
  enabled/paused badge, each linking to the campaign page. A **New campaign** form takes name,
  target, adapter (`echo` until the adapters run their tools, as for the launcher) and interval in
  minutes, default 60. The API's refusal is shown as returned: interval floor, out of scope (with
  the reason), not active, or no permission (403).
- **Campaign page** `/eng/:id/campaigns/:cid`: header with name, adapter, interval and next run;
  **Pause** / **Resume** (PATCH `enabled`); the campaign's runs (state badge and failure reason, as
  in spec 015), refreshed while one is queued or running; its diffs, newest first. Each diff shows
  `baseline` (with its finding count), or `worsened` and counts of new, regressed, resolved and
  unchanged, with the new, regressed and resolved entries listed by rule, severity and title. Also
  the campaign's alerts with state and attempts. A 403 on alerts (viewer) hides that section
  instead of erroring.
- `api.ts`: `listCampaigns`, `getCampaign`, `createCampaign`, `updateCampaign`, `listCampaignRuns`,
  `listCampaignDiffs`, `listAlerts`.

## Behaviour

1. Titles in diff entries are untrusted text and are rendered as text.
2. Creating invalidates the campaign list. Pause/Resume invalidates the campaign and the list.
3. The runs list polls every 5 s (`RUN_POLL_MS`) while a campaign run is queued or running. When
   one finishes, diffs and alerts refresh.
4. The diff list is capped at the API default (20). There is no paging.

## Acceptance criteria

- [ ] Campaigns panel lists campaigns, links to the campaign page, and creates one; refusals show
      the API's message.
- [ ] Campaign page shows header, runs, diffs (baseline / worsened / counts / escaped entries) and
      alerts; Pause/Resume calls the API and updates the badge.
- [ ] A viewer sees no alerts section and no error.
- [ ] `pnpm lint`, `pnpm test`, `pnpm build` pass.

## Test cases

`web/src/__tests__/campaigns.test.tsx`: panel list + create (success and 422 message); campaign
page with a baseline and a worsened diff (counts, entries, escaped title); pause toggles via
`updateCampaign`; alerts hidden on 403.

## Out of scope

- Editing a campaign's template (adapter, target, params): create a new campaign instead.
- Charts of findings over time (a later monitoring view).
