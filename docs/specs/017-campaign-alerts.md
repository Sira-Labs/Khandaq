# Spec 017 — Alerts on a worsened campaign diff

Sprint 5, story S5-2. Depends on: 016. Packages: `api/` (alerts, worker, migration 0009), `deploy/`.

## Goal

When a campaign run's diff is `worsened` (new or regressed findings, spec 016), the deployment's
operators hear about it without watching the console. The alert is sent as a signed webhook
(JSON; works with any receiver, including a chat-ops bridge). It is queued in an **outbox** in the
same transaction as the diff, so a worker crash can't lose it. Delivery is retried with backoff and
every attempt is audited.

## User story

As an engagement owner, I get a message in our team channel when a weekly campaign finds something
new or something that had been fixed comes back, with a link to the diff.

## Interface

- **Config.**

  | Key | Meaning | Default |
  |---|---|---|
  | `KHANDAQ_ALERT_WEBHOOK_URL` | where alerts are POSTed; empty = alerts off | empty |
  | `KHANDAQ_ALERT_WEBHOOK_SECRET` | HMAC-SHA256 key for `X-Khandaq-Signature` (≥ 32 characters) | empty |
  | `KHANDAQ_ALERT_MAX_ATTEMPTS` | delivery attempts before an alert is given up | `5` |

  The URL is deployment configuration, not user input. A per-campaign URL would let any operator
  send engagement data to a host of their choosing, so there is none.
- **Table (migration 0009).** `alert_outbox`: `id` (`alr_…`), `engagement_id`, `campaign_id`,
  `diff_id` (unique), `payload` (jsonb), `state` (`pending` | `sent` | `failed`), `attempts`,
  `next_attempt_at`, `last_error`, `created_at`, `sent_at`. Index `(state, next_attempt_at)`.
- **Payload** (`khandaq.alert/1`): `{schema, kind: "campaign.worsened", engagement: {id, name},
  campaign: {id, name}, run_id, diff_id, counts: {new, regressed, resolved, unchanged}, new: [{rule_id,
  severity}], regressed: [{rule_id, severity}], url}`. `url` is
  `KHANDAQ_PUBLIC_URL/eng/<engagement>`. It carries no finding titles, evidence or target details:
  only what an operator needs to decide to open the console.
- **Headers.** `Content-Type: application/json`, `X-Khandaq-Event: campaign.worsened`,
  `X-Khandaq-Delivery: <alert id>`, and `X-Khandaq-Signature: sha256=<hex HMAC of the body>` when a
  secret is set.
- **Audit.** `alert.queued`, `alert.sent` `{alert_id, status}`, `alert.failed` `{alert_id, attempts,
  error}` (`error` is an HTTP status or an exception class, never the response body).
- **API.** `GET /api/engagements/{id}/alerts` (owner, operator, analyst): the engagement's outbox rows,
  newest first, without payload secrets (there are none).

## Behaviour

1. **Queue.** In the transaction that records a `worsened` diff (spec 016 §4), if alerts are on
   (URL set), an `alert_outbox` row is added with the payload, `state = pending`, and
   `next_attempt_at = now`, and `alert.queued` is recorded. Alerts off → nothing is queued. A
   baseline, or a diff that is not worsened, never alerts.
2. **Deliver (worker).** Each loop iteration, after scheduling campaigns, the worker takes up to 10
   due pending rows (`FOR UPDATE SKIP LOCKED`) and POSTs each payload (10 s timeout, no redirects
   followed).
   - 2xx → `sent`, `sent_at`, `alert.sent`.
   - Anything else (other status, timeout, connection error) → `attempts += 1`, `last_error`, and
     `next_attempt_at = now + 2^attempts minutes` (capped at 60). At `KHANDAQ_ALERT_MAX_ATTEMPTS`
     → `failed` with `alert.failed`.
   - Each row's outcome commits on its own. The POST happens while the row is locked, so two
     workers never send the same alert twice. A crash between the POST and the commit can repeat
     one delivery; receivers deduplicate on `X-Khandaq-Delivery`.
3. **Turned off later.** If the URL is unset while rows are pending, they stay pending (nothing is
   sent anywhere) until it is set again.
4. **Validation.** In prod, a webhook URL that is not `https://`, or a secret under 32 characters
   when a URL is set, stops the app from starting. `http://` is allowed outside prod (local
   receivers).

## Acceptance criteria

- [x] A worsened diff with alerts on queues exactly one outbox row with the documented payload
      (no titles, no evidence), and `alert.queued`; a baseline, an unchanged diff, or alerts off
      queue nothing.
- [x] The worker delivers with the documented headers and a verifiable HMAC; 2xx → `sent` +
      `alert.sent`.
- [x] Failures back off (`next_attempt_at` grows) and end `failed` + `alert.failed` after the
      maximum attempts; the error recorded is a status or exception class.
- [x] Two workers never deliver the same row concurrently.
- [x] `GET /alerts` lists the engagement's alerts for owner/operator/analyst; viewer 403.
- [x] Prod refuses a non-https URL or a short secret.

## Test cases

Integration (`api/tests/test_alerts.py`, Postgres; delivery through an injected HTTP sender, so no
network): queue on worsened / not on baseline / not when off; delivery success with headers and
HMAC check; retry/backoff to failed; locked row skipped by a second worker; list endpoint authz.
Unit (`test_settings.py`): prod URL/secret validation.

> Notes (2026-10-03): the alert tests live in `test_campaigns.py` next to the campaign fixtures.
> Delivery outcomes commit per row; the POST happens under the row lock, so a crash between POST
> and commit can repeat one delivery (receivers deduplicate on `X-Khandaq-Delivery`).

## Out of scope

- Email delivery (SMTP), as a second channel on the same outbox.
- Per-engagement or per-campaign routing.
- Alerts on report verification failures or ledger breaks (a later monitoring spec).
