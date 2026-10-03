# Deploying Khandaq

Three paths:

- **CapRover one-click** — the whole stack from one form (staging or a solo instance). See
  [`caprover/one-click/`](caprover/one-click/).
- **CapRover app-by-app** (staging + production with digest promotion), the family standard — see
  [`caprover.md`](caprover.md).
- **Single-box self-host** with `docker compose` for one operator on a trusted machine — below.

> `ghcr.io/sira-labs/khandaq-api` and `-web` are published by CI (`.github/workflows/release.yml`) on
> every push to `main`. The current images are the **bootable R1 skeleton**: the API serves
> `/api/health` and `/api/version` (fail-closed in prod) and the web app serves the landing page and
> proxies `/api`; the engagement, scope-lock, findings and adapter features land spec by spec. The
> adapter images (`khandaq-adapter-*`) arrive with spec 006.

## Single-box self-host

```bash
cd deploy
cp .env.example .env         # fill in secrets; prod refuses placeholders
docker compose up            # api, worker, postgres, rustfs, web on http://127.0.0.1:8080
docker compose --profile demo up   # … plus the bundled vulnerable target for `make demo`
```

The first command brings up the control plane, a Postgres and a RustFS object store for evidence.
The second also starts the bundled **intentionally-vulnerable local target**, so you can run
`make demo` without pointing at any third-party system. Adapter containers are launched by the worker
per run via the host Docker socket (shape A in `caprover.md`); only use this on a trusted machine.

## What you must provide (ADR-0006)

- `KHANDAQ_SESSION_SECRET` — `openssl rand -base64 48`
- `KHANDAQ_EVIDENCE_KEY` — the envelope key that encrypts captured evidence at rest (ADR-0016): any
  string of at least 32 characters, e.g. `openssl rand -base64 32`. Production refuses a shorter one.
  **Back it up separately; losing it makes evidence unreadable** (the ledger still verifies, but the
  bytes cannot be decrypted). To rotate, set the new key and move the old one to
  `KHANDAQ_EVIDENCE_PREVIOUS_KEYS`; stored objects are never re-encrypted.
- object-store credentials (RustFS root + a bucket-scoped key). Evidence is stored encrypted and
  write-once in `KHANDAQ_OBJECT_STORE_URL` (`s3://bucket[/prefix]`); with an empty URL it stays in the
  worker's evidence volume, which the API cannot read on a multi-host deployment.
- OIDC settings for anything beyond a single-user local run

## Campaigns and alerts (specs 016, 017)

The worker re-runs campaigns on their interval (never more often than
`KHANDAQ_CAMPAIGN_MIN_INTERVAL_MINUTES`, default 60) and records what changed. To be told when a
campaign gets worse, set `KHANDAQ_ALERT_WEBHOOK_URL` (https in prod) and
`KHANDAQ_ALERT_WEBHOOK_SECRET` on the **worker**. Alerts carry rule ids and counts, not finding text,
and are retried with backoff (`KHANDAQ_ALERT_MAX_ATTEMPTS`, default 5).

## Smoke test after a deploy (spec 019)

Sign in, open **API tokens** in the console header, create a token, then run:

```sh
KHANDAQ_TOKEN=khq_... python3 deploy/smoke.py --url https://khandaq-stg.example.org
```

The script needs only the Python 3.10+ standard library. It prints one line per check (health and
schema, token sign-in, engagement + scope lock, an echo run, the ledger, report export and
re-verification, the evidence route, a paused campaign, alerts, close) and exits 0 when all pass.
It uses the in-process `echo` adapter against `smoke.khandaq.invalid`, so nothing leaves the API.
It closes the engagement it creates. Revoke the token afterwards if you do not need it.

## Safe-use reminder

Khandaq runs offensive tooling. Every run must belong to an engagement whose targets you are authorised
to test; the scope lock enforces this. For demos and tests, use the **bundled vulnerable target** only —
never a third-party system. See `SECURITY.md`.

## Backups

For any real use, back up Postgres **and** the evidence object store (it holds the only copy of captured
evidence and the ledger proofs), plus the `KHANDAQ_EVIDENCE_KEY`. Production backup requirements are in
`caprover.md` section 7.
