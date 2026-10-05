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

To get the same alert by email as well (spec 022), set these on the worker:
- `KHANDAQ_ALERT_EMAIL_TO`: comma-separated recipients.
- `KHANDAQ_ALERT_EMAIL_FROM`: the From address.
- `KHANDAQ_SMTP_URL`: your relay, as `smtps://user@mail.example` (port 465) or
  `smtp+starttls://user@mail.example` (port 587).
- `KHANDAQ_SMTP_PASSWORD`: the relay password.

Plain `smtp://` is accepted only outside prod, for a local catcher. Each channel is retried
separately, so a down relay never delays the webhook. A retry after a timeout can deliver an email
twice; the `Message-ID` is stable, so mail filters can drop the duplicate.

## Your own framework mappings (spec 021)

Findings carry ATLAS, OWASP LLM (2025 and 2026) and NIST AI RMF ids from the built-in table. To add
your own ids, or to correct an entry for your context, write an overlay in the same schema and set
`KHANDAQ_MAPPINGS_PATH` to it on the **api and the worker** (mount the file into both):

```json
{
  "schema": "khandaq.mappings/1",
  "versions": {"acme-ctl": "2026.1"},
  "sources": {"acme-ctl": "https://controls.acme.example/"},
  "rules": {
    "garak.leakreplay": {
      "mappings": [{"framework": "acme-ctl", "id": "CTL-7"}],
      "rationale": "our data-handling control"
    }
  }
}
```

Keys are rule-id prefixes (the longest match wins). An overlay key replaces the built-in entry of
the same key, so list the built-in ids too if you want to keep them. You can add frameworks, but you
cannot change a built-in framework's version or source. A file that is missing, larger than 1 MiB,
or invalid stops the app at startup. Every report names the overlay and its sha256. Changes take a
restart, and stored findings are not re-mapped.

## Deployment status (spec 023)

`GET /api/deployment` (organisation admins only) shows what the API and each worker are configured
with:
- whether the evidence key, object store, webhook and email alerts are set;
- the campaign interval floor;
- the mapping table versions and overlay.

No secret, URL or address is shown, only whether each is set. Each worker reports a heartbeat
every 30 s, and `alive` means it reported in the last 2 minutes. After a redeploy, check that at
least one worker is alive and has the alert settings you expect: alerts are worker settings. The
console shows the same on its **Deployment** page (admins only), with warnings when no worker is
alive or a worker's mapping table differs from the API's (spec 024).

## Keycloak answers "Invalid parameter: redirect_uri"

Khandaq sent a callback address the realm does not know. It is `KHANDAQ_PUBLIC_URL` +
`/api/auth/callback`, so check `KHANDAQ_PUBLIC_URL` on the api app: it must be the web console's
https origin (`https://khandaq-stg.siralabs.org` on staging), exactly as the realm file was rendered
for. A value such as `https://$$cap_appname-web.<root domain>` is an unfilled one-click default;
from `sha-` builds after 5 Oct the API refuses to start with one.

## Sign-in says "identity provider cannot be reached"

The API could not talk to Keycloak. The API log names the step and the cause:
- `OIDC discovery failed` — fetching `<KHANDAQ_OIDC_ISSUER>/.well-known/openid-configuration`
  failed (the causes below);
- `OIDC token exchange failed` — discovery worked, but the token endpoint could not be reached or
  answered with a 5xx after the user came back from Keycloak;
- `OIDC signing keys unavailable` — the realm's signing keys (`jwks_uri`) could not be fetched.

For discovery, the error names the cause:
- **`ConnectError: No address associated with hostname`** — the issuer's host does not resolve from
  inside the API container. Use the Keycloak app's public URL (`https://<keycloak host>/realms/khandaq`),
  or its CapRover internal name (`http://srv-captain--<keycloak app>:8080/realms/khandaq`) only if
  that app exists on the same server. Then check that the token issuer Keycloak reports matches
  what browsers see.
- **`HTTPStatusError … 404`** — the host is right but the `khandaq` realm is missing: import
  `deploy/keycloak/khandaq-realm-staging.json` (or `-production.json`) with *Create realm* (see
  `deploy/keycloak/README.md`). If the import itself answers *"unknown_error"*, you uploaded the
  `.template.json`.
- **A timeout or `ConnectError: Connection refused`** — Keycloak is down or not listening there.

Open the discovery URL in a browser: it must return JSON.

## Smoke test after a deploy (spec 019)

Sign in, open **API tokens** in the console header, create a token, then run:

```sh
KHANDAQ_TOKEN=khq_... python3 deploy/smoke.py --url https://khandaq-stg.example.org
```

The script needs only the Python 3.10+ standard library. It prints one line per check (health and
schema, token sign-in, engagement + scope lock, an echo run whose findings carry the core mapping
table's ids, the ledger, report export and re-verification with the mapping table it names, the
evidence route, a paused campaign, alerts, close) and exits 0 when all pass. With an admin's token
it also checks that a worker is alive; with any other token that check is reported as skipped.
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
