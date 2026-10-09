# Deploying Khandaq on CapRover

CapRover provides the reverse proxy, TLS and container scheduling. The web app's Caddy proxies `/api`
to the control-plane API over the internal network; the worker launches **adapter containers** per run,
which is the one way Khandaq's deployment differs from Thawr/Tabayyun and needs care (see
"Adapter execution and egress", below).

> **Fastest path — one-click.** To stand up a single instance (staging or a solo operator) in one step,
> use the CapRover **one-click app** at [`caprover/one-click/khandaq.yml`](caprover/one-click/) — it
> deploys the whole stack (db, evidence store, api, worker, web) with generated secrets. The
> app-by-app guide below is for the **staging + production split with digest promotion** (ADR-0010),
> which real client-engagement data needs.

```
Internet ─▶ CapRover nginx (TLS) ─▶ khandaq-web (Caddy :80) ──/api──▶ khandaq-api (:8000)
                                                                          │
                                        khandaq-worker ──launches──▶ adapter containers (per run)
                                                                          │  egress: in-scope target only
                                        khandaq-db (PostgreSQL) · object store (RustFS) · Keycloak
```

## Staging and production (ADR-0010)

Two independent CapRover servers at Hetzner, following the Sīra family split (Tabayyun ADR-0016,
Arqam ADR-0020). **Engagement data and captured evidence live only on production.**

| Server | Apps | Domain | Data |
|---|---|---|---|
| **Staging & tools** (current server) | `khandaq-stg-db`, `khandaq-stg-api`, `khandaq-stg-worker`, `khandaq-stg-web`, `khandaq-stg-rustfs`; GlitchTip + uptime for both | `khandaq-stg.siralabs.org` | test data only |
| **Production** (Germany) | `khandaq-db`, `khandaq-api`, `khandaq-worker`, `khandaq-web`, `khandaq-rustfs`, Keycloak | `khandaq.siralabs.org` | real engagement data & evidence, only here |

App names follow `<app>-<role>` with `<app>` = `khandaq-stg` on staging and `khandaq` on production —
exactly what the one-click produces when you give it that app name. Rules:

- Real engagement data and captured evidence live **only** on production. Staging holds synthetic data.
- Staging and production have separate secrets: DB passwords, session secret, object-store keys, OIDC
  clients, CapRover app tokens, **and the evidence-encryption key** (ADR-0006) — production-only.
- Every push to `main` publishes `ghcr.io/sira-labs/khandaq-api` and `-web` as `latest` and
  `sha-<short sha>` (`release.yml`). **Nothing redeploys staging yet**: redeploy `-api`, `-worker` and
  `-web` yourself (Deploy via ImageName), preferably with the `sha-…` tag, because a host can keep
  serving a cached `latest`. Then check `/api/version` shows the newest migration and, with an
  admin token, that `GET /api/deployment` lists an alive worker (spec 023). Production runs the
  **image digest staging ran**, after the owner approves it (promotion, ADR-0010).
- Production Postgres is backed up continuously; the evidence object store is versioned and copied,
  encrypted, to a second location; restore drills run into a throwaway DB on production, never staging.

### Per-environment values

Sections below show the production names; on staging use the right-hand column. The **public origin**
row is the one that must be identical everywhere it appears — a mismatch makes Keycloak reject sign-in
with *"Invalid parameter: redirect_uri"*.

| Value | Production | Staging |
|---|---|---|
| App names | `khandaq-db`, `-api`, `-worker`, `-web`, `-rustfs` | `khandaq-stg-db`, `-api`, `-worker`, `-web`, `-rustfs` |
| **Public origin** — the domain on the **web** app, `KHANDAQ_PUBLIC_URL` on the api, and the origin the realm file is rendered for | `https://khandaq.siralabs.org` | `https://khandaq-stg.siralabs.org` |
| Keycloak client redirect URI (set in the ready-made realm file) | `https://khandaq.siralabs.org/api/auth/callback` | `https://khandaq-stg.siralabs.org/api/auth/callback` |
| `KHANDAQ_API_UPSTREAM` on the web app | `srv-captain--khandaq-api:8000` | `srv-captain--khandaq-stg-api:8000` |
| Database host in the DB URLs | `srv-captain--khandaq-db:5432` | `srv-captain--khandaq-stg-db:5432` |
| `KHANDAQ_OBJECT_STORE_ENDPOINT` | `http://srv-captain--khandaq-rustfs:9000` | `http://srv-captain--khandaq-stg-rustfs:9000` |
| `KHANDAQ_OIDC_ISSUER` | `https://<prod keycloak>/realms/khandaq` | `https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq` (the shared Keycloak, next to `tabayyun` and `sahifa`) |
| `KHANDAQ_OIDC_CLIENT_ID` | `khandaq-api` | `khandaq-api` — the **OIDC client** in the realm, not the CapRover app; never `khandaq-stg-api` |
| `KHANDAQ_ENV` | `prod` | `prod` — staging is public too, so the dev login stub must stay off |

Staging and production never share a Keycloak: production has its own (section 5), so both realms are
called `khandaq`.

## 1. Database app: `khandaq-db` (staging: `khandaq-stg-db`)

- Create a plain app `khandaq-db` with **Has Persistent Data** ticked.
- *Deploy via ImageName*: `postgres:17` (pin the digest; bump deliberately with a migration check).
- App Configs:
  - Env: `POSTGRES_USER=khandaq`, `POSTGRES_PASSWORD=<openssl rand -hex 24>`, `POSTGRES_DB=khandaq`.
  - Persistent directory: `/var/lib/postgresql/data`, label `khandaq-pgdata`.
  - No host port; the API reaches it at `srv-captain--khandaq-db:5432`.
- Confirm the persistent directory shows in App Configs **before** any real data — without it a restart
  starts an empty database (CapRover cannot add persistent data to an existing app).

## 2. API app: `khandaq-api` (staging: `khandaq-stg-api`)

- Create `khandaq-api` (persistent data ticked if any local cache is used; evidence lives in the object
  store, not here).
- Env:

  | Name | Value |
  |---|---|
  | `KHANDAQ_ENV` | `prod` |
  | `KHANDAQ_MIGRATION_DATABASE_URL` | `postgresql+psycopg://khandaq:<pw>@srv-captain--khandaq-db:5432/khandaq` (owner; migrations) |
  | `KHANDAQ_DATABASE_URL` | `postgresql+psycopg://khandaq_app:<app pw>@srv-captain--khandaq-db:5432/khandaq` — a **separate runtime login with its own password** (`openssl rand -hex 24`). The API creates it on first boot and re-checks it on every boot: row access only, so a compromised API cannot rewrite or truncate the audit/evidence/ledger tables or disable their triggers. It never changes an existing login's password; to rotate it, run `ALTER ROLE khandaq_app PASSWORD '…'` as the owner, then update this URL. The API drops the owner URL before it starts serving. |
  | `KHANDAQ_SESSION_SECRET` | `openssl rand -base64 48` |
  | `KHANDAQ_OBJECT_STORE_URL` | `s3://khandaq-evidence` |
  | `KHANDAQ_OBJECT_STORE_ENDPOINT` | `http://srv-captain--khandaq-rustfs:9000` |
  | `KHANDAQ_OBJECT_STORE_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | the bucket-scoped key (section 4) |
  | `KHANDAQ_EVIDENCE_KEY` | the envelope-encryption key for evidence (ADR-0006); **production-only** |
  | `KHANDAQ_PUBLIC_URL` | the public origin: `https://khandaq.siralabs.org` (staging `https://khandaq-stg.siralabs.org`) — the web app's domain, exactly |
  | `KHANDAQ_OIDC_ISSUER` | the realm, e.g. `https://<keycloak>/realms/khandaq` |
  | `KHANDAQ_OIDC_CLIENT_ID` | `khandaq-api` (the default; the realm's client, not this app's name) |
  | `KHANDAQ_OIDC_CLIENT_SECRET` | the realm's `khandaq-api` client secret (section 5) |
  | `KHANDAQ_ADMIN_EMAIL` | the owner's email; becomes admin at first verified sign-in |
  | `KHANDAQ_ALLOWED_EMAILS` | other people who may sign in, comma-separated (empty = owner only). The realm brokers any Google/GitHub account; everyone not listed lands on "no access" and is audited as `auth.denied` |
  | `KHANDAQ_SIGSTORE` | `off` (default) or `on` |

  Users are bound to their Keycloak account (`iss` + `sub`) at first sign-in. If a Keycloak user is
  deleted and recreated, the new account gets a new `sub`, and its sign-in is refused (`auth.denied`:
  "email is linked to another identity-provider account") so a second account can never inherit the
  first one's engagements. After confirming it is the same person, unlink the old account so the next
  sign-in links the new one:
  `UPDATE users SET oidc_issuer = NULL, oidc_subject = NULL WHERE email = '<their email>';`

  With `KHANDAQ_ENV=prod` the API refuses to start without the DB, session, evidence-key and OIDC
  settings (fail closed). The worker needs the same minus OIDC — it serves no logins and is not given
  the client secret.
- The image runs migrations on start before serving; `GET /api/version` reports `schema_revision`.
- Container HTTP port `8000`. No public domain needed (the web app proxies to it).
- Deployment tab → **Enable App Token**, copy it into the GitHub secret for CI.

## 3. Worker app: `khandaq-worker` (staging: `khandaq-stg-worker`)

Runs execute here, not in the API. Create `khandaq-worker` with the api image and `KHANDAQ_ROLE=worker`
plus the same DB/object-store/evidence-key/session env as the API — `KHANDAQ_DATABASE_URL` (the
`khandaq_app` runtime login) but **not** `KHANDAQ_MIGRATION_DATABASE_URL`: only the API migrates.
**No HTTP port, no domain.**

### Adapter execution and egress — the important part

The worker launches an adapter **container per run** (ADR-0009), each with egress restricted to the one
in-scope target. On CapRover there are two supported shapes; pick one per server and document it:

- **A — Docker-out-of-Docker (simple).** Mount the host Docker socket into the worker so it can
  `docker run` pinned adapter images with a per-run network and an egress firewall that allows only the
  resolved target host/port. This is the straightforward route; treat the worker as privileged and keep
  it on its own server (do not co-locate untrusted apps).
- **B — Dedicated adapter-runner host (preferred for production).** A separate, locked-down host (or a
  small pool) that the worker drives over an authenticated API; adapter images run there with a
  default-deny egress policy and a per-run allow-rule for the target. This isolates the privileged
  launch surface from the control plane entirely. Recommended once real client engagements run.

Either way: adapter images are pinned and pulled from GHCR; air-gapped installs mirror them into a local
registry; egress is **default-deny** with a per-run allow for the target only.

**Shape A, as implemented (spec 012).** No host firewall rules are needed. Each run gets an
`--internal` Docker network, so it has no route out. Its only other member is a small forwarder
(`KHANDAQ_FORWARDER_IMAGE`, the same `khandaq-api` image) that answers to the target's hostname and
relays to the one address the worker resolved. The CI `e2e` job proves the adapter reaches its
target and cannot reach a decoy on the same network. On the worker app:

- **Socket.** Mount `/var/run/docker.sock`, and add the host's `docker` group
  (`getent group docker`) to the container. In CapRover, use the app's *Service Update Override*,
  for example:
  `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Target":"/var/run/docker.sock"}],"Groups":["<gid>"]}}}`.
- **Persistent directory.** Only needed when `KHANDAQ_OBJECT_STORE_URL` is empty: then
  `/var/lib/khandaq/evidence` holds the runs' evidence bytes, encrypted and written once, and the
  API (another app) cannot serve downloads from it. With the object store set (the default), the
  worker uploads there (spec 014).
- **Environment:**
  - `KHANDAQ_FORWARDER_IMAGE=ghcr.io/sira-labs/khandaq-api:<the worker's own tag>`;
  - `KHANDAQ_ADAPTER_EGRESS_NETWORK=bridge`, the default; it routes out to authorised remote
    targets;
  - optionally `KHANDAQ_ADAPTER_TIMEOUT_SECONDS`.

## 4. Object store: `khandaq-rustfs` (staging: `khandaq-stg-rustfs`)

Evidence lives on S3-compatible storage, append-only. Use RustFS (Apache-2.0).

1. App `khandaq-rustfs`: *Deploy via ImageName* `rustfs/rustfs:1.0.0` (pin the tag), persistent
   directory `/data`, env `RUSTFS_ACCESS_KEY`/`RUSTFS_SECRET_KEY` (strong root), container port `9000`.
   No public domain for the S3 API; open the console (9001) only over an SSH tunnel.
2. In the console: create bucket `khandaq-evidence` with **object versioning on** (so the append-only
   guarantee is backed by the store), and a bucket-scoped access key for the API/worker. Enable a
   write-once/retention policy on sealed objects where the store supports it. If the bucket is
   missing and the key may create buckets (the one-click passes the root key), the worker creates it
   on the first upload and enables versioning itself.
3. What Khandaq does with it (spec 014, ADR-0016): every evidence file is encrypted with its own
   data key, wrapped under a key derived from `KHANDAQ_EVIDENCE_KEY`, and uploaded with
   `If-None-Match: *` after a `HEAD`, so a sealed object is never overwritten (RustFS 1.0.0 honours
   the condition; CI checks it). The bucket-scoped key needs `s3:GetObject`, `s3:PutObject` and
   `s3:ListBucket` (for `HEAD`) on the bucket. The API and the worker need the same object-store
   settings and the same evidence key (and retired keys). Downloads: `GET
   /api/engagements/{id}/evidence/{evidence_id}/content` (owner/operator/analyst; audited).

## 5. Keycloak (each environment, before the first sign-in)

Both environments run `KHANDAQ_ENV=prod`, so both need a realm — there is no password or dev login on
a deployed server. One realm per install, as for Tabayyun and Sahifa: **staging** uses realm
`khandaq` on the shared Keycloak `miftachun.apps.data-and-ai-dude.ch`; **production** gets its own
Keycloak. The realm defines the confidential `khandaq-api` client (Authorization Code + PKCE,
back-channel logout), the Google/GitHub brokers and the passkey browser flow, with no secrets baked
in.

1. **Import the realm.** Download the ready-made file for the environment —
   [`keycloak/khandaq-realm-staging.json`](keycloak/khandaq-realm-staging.json) or
   [`keycloak/khandaq-realm-production.json`](keycloak/khandaq-realm-production.json) — then
   Keycloak admin console → realm drop-down → **Create realm** → *Resource file*: that file →
   **Create**. Not the `.template.json`: Keycloak refuses its placeholder with *"unknown_error"*.
   Not *Partial import*: it skips the flows and leaves a broken realm.
2. **Check** that `https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq/.well-known/openid-configuration`
   (staging) answers JSON, not 404.
3. **Client secret.** Realm `khandaq` → Clients → `khandaq-api` → Credentials → Regenerate; copy it
   into the api app's `KHANDAQ_OIDC_CLIENT_SECRET`.
4. **Google and GitHub.** Create an OAuth client for each (Khandaq's own, not Tabayyun's) with the
   redirect `https://<keycloak>/realms/khandaq/broker/google/endpoint` or
   `…/broker/github/endpoint`, and paste the id and secret into Identity providers → `google` /
   `github` → Save.
5. **API settings.** `KHANDAQ_OIDC_ISSUER=https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq`
   on staging (the public URL; never a CapRover internal name), then Save & Update.

The ready-made files are rendered for `https://khandaq-stg.siralabs.org` and
`https://khandaq.siralabs.org`. For another domain, render the template with
`python3 deploy/keycloak/render.py https://<origin> > khandaq-realm.json`, and update
`KHANDAQ_PUBLIC_URL` together with it. Full steps: [`keycloak/README.md`](keycloak/README.md).

## 6. Web app: `khandaq-web` (staging: `khandaq-stg-web`)

Create `khandaq-web` with the web image. Env `KHANDAQ_API_UPSTREAM=srv-captain--khandaq-api:8000`
(staging `srv-captain--khandaq-stg-api:8000`). Connect the public domain — `khandaq.siralabs.org`
(staging `khandaq-stg.siralabs.org`) — to **this web app** and enable HTTPS; the API app stays on *Do
not expose as web-app*. The web app is the single entrance: Caddy serves the SPA and proxies `/api`, so
the session cookie and the redirect URI all live on one origin.

## 7. Backups (production)

- Postgres: continuous WAL archiving (WAL-G or pgBackRest) on physical base backups (weekly full, daily
  delta, ≥2 fulls kept) **and** a nightly `pg_dump -Fc`.
- Evidence: a versioned, encrypted copy of the `khandaq-evidence` bucket to a second Hetzner location —
  it holds the only copy of captured evidence and the ledger-backed proofs.
- All encrypted; restore drills into a throwaway DB on production, timed, then dropped. Never restore
  into staging (it would mix real evidence into test).

## 8. CI/CD (GitHub environments)

Today `release.yml` builds the control-plane, web and adapter images once per commit and publishes them
to GHCR (`latest` on `main`, a short-SHA tag, and `v*` tags). It does **not** deploy yet: update the
staging apps by redeploying them in CapRover (they pull `latest`).

Planned (ADR-0010, tracked in `TASKS.md`): a deploy step that pushes `main` to the `staging`
environment's apps via CapRover app tokens, and `promote.yml` that deploys the **same digests** to
`production` after the owner (required reviewer) approves. CapRover tokens, the deploy key and server
variables will live on those GitHub environments, not at repo level. A tag ruleset limits `v*` tags to
org admins.

## Testing with garak: the demo target or your own Ollama (spec 027)

garak runs in the sandbox against an **OpenAI-compatible** endpoint that the engagement authorises.
On staging, use a target that lives on the same server and is not published:
- the bundled demo target;
- your own Ollama with a small model.

**1. A target app, internal only.** Create the app and tick **Do not expose as web app**, so it has
no domain and is reachable only on CapRover's overlay network as `srv-captain--<app>`.
- **Demo target.** App `khandaq-stg-target`, *Deploy via ImageName*
  `ghcr.io/sira-labs/khandaq-vulnerable-target:sha-<short sha>`, container port `8900`.
  - Target URL: `http://srv-captain--khandaq-stg-target:8900/v1/chat/completions`.
  - Model: any name, for example `demo`.
- **Ollama.** App `khandaq-stg-ollama`, *Deploy via ImageName* `ollama/ollama:<exact tag>`,
  persistent directory `/root/.ollama`, container port `11434`.
  1. Pull a small model once, from the server:
     `docker exec $(docker ps -qf name=srv-captain--khandaq-stg-ollama) ollama pull llama3.2:1b`.
  2. Target URL: `http://srv-captain--khandaq-stg-ollama:11434/v1/chat/completions`.
  3. Model: `llama3.2:1b`.

**2. The worker reaches it through the overlay.** On the worker app, set
`KHANDAQ_ADAPTER_EGRESS_NETWORK=captain-overlay-network`. The per-run forwarder joins that network:
- it can relay to `srv-captain--…` addresses, which the worker resolves and checks;
- it still routes out to remote targets.

Keep the socket mount and `KHANDAQ_FORWARDER_IMAGE` from section 3. The first garak run pulls
`ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0`, which is about 600 MB to download, so allow for that once.

**3. In the console** (spec 026):
1. Create an engagement.
2. Add an *LLM endpoint* target with the URL and model above.
3. Save the scope **without** a requests-per-minute limit. garak cannot hold a rate cap, so a capped
   engagement refuses it (spec 027).
4. Activate the engagement.
5. Under *Run a suite*, choose **garak 0.17.0**, the target, and optionally probe names.
6. Press Run.

The run is queued, and the worker runs it. It ends either:
- **succeeded**, with findings and garak's report and hit log as evidence;
- or **failed**, with garak's last output as the reason.

A CPU-only Ollama answers slowly. Keep the default probe set for a first run and raise
`KHANDAQ_ADAPTER_TIMEOUT_SECONDS` (default 3600) for longer ones.

Only point garak at systems you are authorised to test. The scope lock refuses any other target.

## Local self-host (one box)

`cd deploy && cp .env.example .env && docker compose up` brings up api, worker, Postgres, RustFS and
(optionally) Keycloak, plus the bundled vulnerable local target for `make demo`. The compose file uses
shape **A** for adapter execution (host Docker socket) and is for a single operator on a trusted machine,
not a shared/production host.
