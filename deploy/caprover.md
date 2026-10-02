# Deploying Khandaq on CapRover

CapRover provides the reverse proxy, TLS and container scheduling. The web app's Caddy proxies `/api`
to the control-plane API over the internal network; the worker launches **adapter containers** per run,
which is the one way Khandaq's deployment differs from Thawr/Tabayyun and needs care (see
"Adapter execution and egress", below).

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
| **Staging & tools** (current server) | `khandaq-db-stg`, `khandaq-api-stg`, `khandaq-worker-stg`, `khandaq-web-stg`, a staging object store; GlitchTip + uptime for both | `khandaq-stg.siralabs.org` | test data only |
| **Production** (Germany) | `khandaq-db`, `khandaq-api`, `khandaq-worker`, `khandaq-web`, its own object store, Keycloak | `khandaq.siralabs.org` | real engagement data & evidence, only here |

Every staging app name and every internal address that names an app gets the `-stg` suffix. Rules:

- Real engagement data and captured evidence live **only** on production. Staging holds synthetic data.
- Staging and production have separate secrets: DB passwords, session secret, object-store keys, OIDC
  clients, CapRover app tokens, **and the evidence-encryption key** (ADR-0006) — production-only.
- `main` deploys to staging automatically; production runs the **image digest staging ran**, after the
  owner approves it (promotion, ADR-0010).
- Production Postgres is backed up continuously; the evidence object store is versioned and copied,
  encrypted, to a second location; restore drills run into a throwaway DB on production, never staging.

Sections below name the production apps; on staging add `-stg`.

## 1. Database app: `khandaq-db`

- Create a plain app `khandaq-db` with **Has Persistent Data** ticked.
- *Deploy via ImageName*: `postgres:17` (pin the digest; bump deliberately with a migration check).
- App Configs:
  - Env: `POSTGRES_USER=khandaq`, `POSTGRES_PASSWORD=<openssl rand -hex 24>`, `POSTGRES_DB=khandaq`.
  - Persistent directory: `/var/lib/postgresql/data`, label `khandaq-pgdata`.
  - No host port; the API reaches it at `srv-captain--khandaq-db:5432`.
- Confirm the persistent directory shows in App Configs **before** any real data — without it a restart
  starts an empty database (CapRover cannot add persistent data to an existing app).

## 2. API app: `khandaq-api`

- Create `khandaq-api` (persistent data ticked if any local cache is used; evidence lives in the object
  store, not here).
- Env:

  | Name | Value |
  |---|---|
  | `KHANDAQ_ENV` | `prod` |
  | `KHANDAQ_MIGRATION_DATABASE_URL` | `postgresql+psycopg://khandaq:<pw>@srv-captain--khandaq-db:5432/khandaq` (owner; migrations) |
  | `KHANDAQ_DATABASE_URL` | `postgresql+psycopg://khandaq_app:<app pw>@srv-captain--khandaq-db:5432/khandaq` (app login) |
  | `KHANDAQ_SESSION_SECRET` | `openssl rand -base64 48` |
  | `KHANDAQ_OBJECT_STORE_URL` | `s3://khandaq-evidence` |
  | `KHANDAQ_OBJECT_STORE_ENDPOINT` | `http://srv-captain--khandaq-rustfs:9000` |
  | `KHANDAQ_OBJECT_STORE_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | the bucket-scoped key (section 4) |
  | `KHANDAQ_EVIDENCE_KEY` | the envelope-encryption key for evidence (ADR-0006); **production-only** |
  | `KHANDAQ_PUBLIC_URL` | `https://khandaq.siralabs.org` |
  | `KHANDAQ_OIDC_ISSUER` | the realm, e.g. `https://<keycloak>/realms/khandaq` |
  | `KHANDAQ_OIDC_CLIENT_SECRET` | the realm's `khandaq-api` client secret (section 5) |
  | `KHANDAQ_ADMIN_EMAIL` | the owner's email; becomes admin at first verified sign-in |
  | `KHANDAQ_SIGSTORE` | `off` (default) or `on` |

  With `KHANDAQ_ENV=prod` the API refuses to start without the DB, session, object-store, evidence-key
  and OIDC settings (fail closed).
- The image runs migrations on start before serving; `GET /api/version` reports `schema_revision`.
- Container HTTP port `8000`. No public domain needed (the web app proxies to it).
- Deployment tab → **Enable App Token**, copy it into the GitHub secret for CI.

## 3. Worker app: `khandaq-worker`

Runs execute here, not in the API. Create `khandaq-worker` with the api image and `KHANDAQ_ROLE=worker`
plus the same DB/object-store/evidence-key/session env as the API. **No HTTP port, no domain.**

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
registry; egress is **default-deny** with a per-run allow for the target only, and a negative test (the
echo adapter cannot reach a second host) runs in CI (spec 005).

## 4. Object store: `khandaq-rustfs`

Evidence lives on S3-compatible storage, append-only. Use RustFS (Apache-2.0).

1. App `khandaq-rustfs`: *Deploy via ImageName* `rustfs/rustfs:1.0.0` (pin the tag), persistent
   directory `/data`, env `RUSTFS_ACCESS_KEY`/`RUSTFS_SECRET_KEY` (strong root), container port `9000`.
   No public domain for the S3 API; open the console (9001) only over an SSH tunnel.
2. In the console: create bucket `khandaq-evidence` with **object versioning on** (so the append-only
   guarantee is backed by the store), and a bucket-scoped access key for the API/worker. Enable a
   write-once/retention policy on sealed objects where the store supports it.

## 5. Keycloak (production, before the first real user)

Create a `khandaq` realm with a confidential `khandaq-api` client (Authorization Code + PKCE), the
redirect URIs for `https://khandaq.siralabs.org`, and brokers (Google/GitHub/passkeys) as the family
does. Put the client secret in `KHANDAQ_OIDC_CLIENT_SECRET`. Single-user staging may run with a local
admin bootstrap, but production requires the realm.

## 6. Web app: `khandaq-web`

Create `khandaq-web` with the web image. Env `KHANDAQ_API_UPSTREAM=srv-captain--khandaq-api:8000`.
Connect the public domain `khandaq.siralabs.org` and enable HTTPS. Caddy serves the SPA and proxies
`/api` to the API.

## 7. Backups (production)

- Postgres: continuous WAL archiving (WAL-G or pgBackRest) on physical base backups (weekly full, daily
  delta, ≥2 fulls kept) **and** a nightly `pg_dump -Fc`.
- Evidence: a versioned, encrypted copy of the `khandaq-evidence` bucket to a second Hetzner location —
  it holds the only copy of captured evidence and the ledger-backed proofs.
- All encrypted; restore drills into a throwaway DB on production, timed, then dropped. Never restore
  into staging (it would mix real evidence into test).

## 8. CI/CD (GitHub environments)

`release.yml` builds and scans the control-plane and adapter images once per commit, publishes to GHCR,
and deploys `main` to the `staging` environment's apps. `promote.yml` deploys the **same digests** to
`production` after the commit is on `main`, staging serves it, and the owner (required reviewer) approves.
CapRover tokens, the deploy key and server variables live on those environments, not at repo level.
A tag ruleset limits `v*` tags to org admins.

## Local self-host (one box)

`cd deploy && cp .env.example .env && docker compose up` brings up api, worker, Postgres, RustFS and
(optionally) Keycloak, plus the bundled vulnerable local target for `make demo`. The compose file uses
shape **A** for adapter execution (host Docker socket) and is for a single operator on a trusted machine,
not a shared/production host.
