# Spec 024 — Console: deployment status page

Sprint 5, story S5-8. Depends on: 023. Packages: `web/`, `docs/`.

## Goal

Spec 023 added `GET /api/deployment`, but an operator still has to open raw JSON to check a redeploy.
When this spec is done, organisation admins have a **Deployment** page in the console. It shows:
- the API's version and schema revision;
- what the API and each worker are configured with;
- whether each worker is alive.

It warns, in words, about the two problems an operator acts on:
- **No live worker:** queued runs will wait.
- **Mismatched mapping tables:** the API and a worker use different mapping-table versions or
  overlays, so their findings would be labelled differently.

## User story

As the admin who just redeployed staging, I open Deployment in the console and see in a glance
that the worker is alive and configured like the API.

## Interface

- **Route** `/deployment`. A **Deployment** link sits in the header, shown only when
  `me.org_role === "admin"`.
- **API client** `api.getDeployment()` → the spec 023 response.
- **Page**:
  - an API card: app version, schema revision, evidence key set, store (and bucket), webhook and
    email alerts on or off, campaign interval floor, mapping versions and overlay;
  - a workers table: id, alive or stale badge, last seen, started, version, alert channels;
  - warnings above both, as `role="alert"` lines.
- It refreshes every 30 s, matching the heartbeat interval.

## Behaviour

1. **403** (not an admin, e.g. the link was typed) → "Organisation admins only." with no data.
   Any other error → the usual load error.
2. **No worker alive** → warning: "No worker has reported in the last 2 minutes: queued runs and
   campaigns will wait." With no worker rows at all, the table says "No worker has reported yet."
3. **Mapping mismatch** → warning naming the worker. A worker counts as mismatched when its
   `mappings.versions` or `mappings.overlay.sha256` differ from the API's.
4. All values are rendered as text. The page never shows a secret, because the endpoint returns none.

## Acceptance criteria

- [x] An admin sees the Deployment link and the page with the API card and worker rows; a member
      sees no link, and the page answers "Organisation admins only." on 403.
- [x] No alive worker shows the warning; an alive worker shows an alive badge and its alerts.
- [x] A worker whose overlay sha256 differs from the API's shows the mismatch warning.

## Test cases

Web (`web/src/__tests__/deployment.test.tsx`): admin view with an alive worker; no live worker
warning; mismatch warning; 403 message; the header link only for admins.

## Out of scope

- Acting on workers (restart, drain).
- History of heartbeats.
