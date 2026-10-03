# Spec 022 — Email as a second alert channel

Sprint 5, story S5-6. Depends on: 017. Packages: `api/` (alerts, settings, migration 0010,
worker), `web/` (campaign alerts list), `deploy/`.

## Goal

Spec 017 sends a signed webhook when a campaign gets worse. It deferred email, the channel most
teams already watch. When this spec is done, a deployment that sets `KHANDAQ_ALERT_EMAIL_TO` also
gets a plain-text email per worsened diff.
- The email goes through the deployment's own SMTP relay and carries the same content as the
  webhook: counts, rule ids, severities and a link, never finding titles, evidence or target
  details.
- Each channel has its own outbox row, retries and audit trail, so a down relay never holds back
  the webhook, and the reverse.

## User story

As an engagement owner without a chat-ops bridge, I get an email when a weekly campaign finds
something new, with a link to the engagement.

## Interface

- **Config** (deployment-level, like the webhook; never per campaign):

  | Key | Meaning | Default |
  |---|---|---|
  | `KHANDAQ_ALERT_EMAIL_TO` | comma-separated recipients; empty = email off | empty |
  | `KHANDAQ_ALERT_EMAIL_FROM` | the From address | empty |
  | `KHANDAQ_SMTP_URL` | `smtps://[user@]host[:465]` (implicit TLS), `smtp+starttls://[user@]host[:587]`, or `smtp://host[:25]` (no TLS; refused in prod) | empty |
  | `KHANDAQ_SMTP_PASSWORD` | the SMTP password, if the URL names a user | empty |

- **Migration 0010.**
  - `alert_outbox.channel`: text, not null, default `webhook`, with a check that it is `webhook`
    or `email`.
  - The unique constraint on `diff_id` becomes unique on `(diff_id, channel)`.
  - Existing rows become `webhook` rows. No row is otherwise changed.
- **Email.**
  - Subject: `[Khandaq] <campaign> got worse: <n> new, <m> regressed`.
  - Body: the engagement and campaign names, the counts, the `rule_id (severity)` lines for new and
    regressed findings, and the link.
  - `Message-ID` is derived from the alert id, so a retried delivery is recognisable.
- **API.** `GET /api/engagements/{id}/alerts` rows gain `channel`.
- **Audit.** `alert.queued`, `alert.sent` and `alert.failed` gain `channel`. For email, `alert.sent`
  records `status: "accepted"` (the relay accepted the message).
- **Console.** The campaign page's alert list shows each row's channel.

## Behaviour

1. **Queue.** In the transaction that records a worsened diff, one row is queued per **enabled**
   channel: webhook when `KHANDAQ_ALERT_WEBHOOK_URL` is set, email when `KHANDAQ_ALERT_EMAIL_TO` is
   set. Each gets its own `alert.queued`. With no channel enabled, nothing is queued.
2. **Deliver.** The worker's batch takes due pending rows of the channels enabled **now**. Rows of
   a channel that was turned off stay pending, as in spec 017 §3.
   - Email goes out over SMTP, with TLS for `smtps` and `smtp+starttls`, authenticating when the
     URL names a user.
   - Each send runs under a hard 10 s deadline. A relay that stalls fails that attempt with
     `TimeoutError` instead of holding the worker.
   - Backoff, attempt limit, `failed` and per-row commit are as in spec 017 §2.
   - The recorded error is the exception class, or the SMTP reply code, never the relay's text.
3. **Header safety.** Campaign and engagement names are user input. CR and LF are replaced with
   spaces before they reach the subject, so a name cannot inject headers.
4. **Validation.**
   - In every environment, setting `KHANDAQ_ALERT_EMAIL_TO` requires `KHANDAQ_SMTP_URL` and a
     From address. Every recipient and the From address must look like an address
     (`local@domain`). A malformed URL, or one carrying a password, stops startup.
   - In prod, the URL must also be `smtps://` or `smtp+starttls://`, with a password when it
     names a user.
   - Outside prod, `smtp://` is allowed (a local catcher).
5. **At-least-once.** A deadline can expire after the relay accepted the message, so a retry may
   deliver it twice. The stable `Message-ID` lets mail clients and filters recognise the duplicate.

## Acceptance criteria

- [x] A worsened diff with both channels on queues one webhook row and one email row, each audited
      with its channel; with only one on, only that one; with neither, nothing.
- [x] The email row is delivered through an injected SMTP sender with the documented subject,
      body, `Message-ID` and recipients, and no finding titles; `alert.sent` records `accepted`.
- [x] A failing or stalled relay backs off and ends `failed` after the maximum attempts. The
      webhook row for the same diff is delivered regardless.
- [x] CR/LF in a campaign name does not reach the subject as a line break.
- [x] Prod refuses email without TLS, or with a user but no password. A missing From, a
      malformed address, or a malformed URL is refused everywhere.
- [x] Migration 0010 keeps existing rows as `webhook` and allows one row per channel per diff.
- [x] `GET /alerts` and the campaign page show the channel.

## Test cases

Integration (`api/tests/test_campaigns.py`, Postgres, injected senders): queue per channel; email
delivery content and subject sanitising; stalled relay → `TimeoutError`, then `SMTP 550`, while
the webhook row is sent; the sender's hard deadline. Migration (`test_migrations.py`): a 0009 row
becomes a webhook row, one row per channel per diff, and a downgrade refuses while email rows
exist. Unit (`test_settings.py`): SMTP validation. Web (`campaigns.test.tsx`): the channel column.

> Notes (2026-10-03): the send runs in a daemon thread joined with the deadline; on expiry the
> attempt is recorded as `TimeoutError` and the thread ends at its next socket timeout. The real
> smtplib path was exercised once against a local catcher; the tests use an injected sender.

## Out of scope

- HTML email, per-recipient preferences, digests.
- Per-engagement or per-campaign recipients (the same exfiltration argument as spec 017).
