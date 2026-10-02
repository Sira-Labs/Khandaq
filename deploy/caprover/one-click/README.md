# Khandaq CapRover one-click app

`khandaq.yml` deploys the **whole Khandaq stack** from one CapRover form:

| Service (app) | Image | Role |
|---|---|---|
| `<app>-db` | `postgres:17` | database (persistent) |
| `<app>-rustfs` | `rustfs/rustfs:1.0.0` | evidence object store (persistent, append-only) |
| `<app>-api` | `ghcr.io/sira-labs/khandaq-api` | control plane (runs migrations on start) |
| `<app>-worker` | `ghcr.io/sira-labs/khandaq-api` | adapter host (launches pinned tool containers) |
| `<app>-web` | `ghcr.io/sira-labs/khandaq-web` | the only public app; proxies `/api` |

Passwords, the session secret, the object-store keys and the **evidence-encryption key** are
generated for you and reused across services.

## Prerequisites

- A CapRover server (ideally **dedicated to Khandaq** — the worker mounts the Docker socket; see
  egress note below).
- An OIDC realm with a confidential **`khandaq-api`** client (Keycloak recommended, ADR-0005). You
  provide its **issuer URL** and **client secret** in the form. The ready-made realm export at
  [`../../keycloak/`](../../keycloak/) sets up exactly this client (plus Google/GitHub and passkeys) —
  render it with the **exact public URL you will enter in the form** (your custom domain, e.g.
  `https://khandaq-stg.siralabs.org`), import it with *Create realm*, then copy the issuer URL and
  client secret into the form.
- Pick the app name per environment: `khandaq-stg` for staging, `khandaq` for production — the apps
  become `<app>-api`, `<app>-web`, … (deploy/caprover.md, "Per-environment values").

## Deploy

1. CapRover dashboard → **Apps** → **One-Click Apps/Databases**.
2. Scroll to the bottom → **"…via text/url"** and paste the **raw** URL of `khandaq.yml`:
   `https://raw.githubusercontent.com/Sira-Labs/Khandaq/main/deploy/caprover/one-click/khandaq.yml`
   (or add this repo as a custom one-click repository).
3. Fill the form: app name, image tag, owner email, the public URL, and the OIDC issuer + client
   secret. Leave the generated secrets as-is.
4. Deploy. Then open **`<app>-web`** (the domain goes on the web app, never on `<app>-api`), connect
   the domain and enable HTTPS. That origin, the Public URL you entered, and the realm's redirect URI
   (`<origin>/api/auth/callback`) must all be the same — otherwise Keycloak answers *"Invalid
   parameter: redirect_uri"*. To fix a mismatch, edit `KHANDAQ_PUBLIC_URL` on `<app>-api` and the
   realm client together.
5. Sign in with the owner email to claim the admin account.

## After deploy — do these

- **Back up the generated `KHANDAQ_EVIDENCE_KEY`** (in the `<app>-api` and `<app>-worker` env). It
  encrypts captured evidence and **cannot be recovered** — losing it makes evidence unreadable (ADR-0006).
- Set up Postgres + evidence-bucket backups per [`../../caprover.md`](../../caprover.md) §7.
- Confirm the `<app>-db` and `<app>-rustfs` apps show their **persistent directories** (one-click sets
  named volumes; verify before real data).

## Egress & isolation (ADR-0009)

This one-click uses **shape A**: the worker launches adapter containers via the host Docker socket and
restricts each run's egress to the single in-scope target. That makes the worker privileged, so run it
on a **server dedicated to Khandaq**. For production with untrusted neighbours, use the **dedicated
adapter-runner host (shape B)** in [`../../caprover.md`](../../caprover.md) instead of this one-click.

## Scope / staging-production

The one-click is the quickest way to stand up a **single instance** (great for staging or a solo
operator). For the **staging + production split with digest promotion** (ADR-0010), follow the
app-by-app guide in [`../../caprover.md`](../../caprover.md); do not run client-engagement data on a
one-click single box without the backup and isolation steps there.

> Images `ghcr.io/sira-labs/khandaq-*` are published by CI (`.github/workflows/release.yml`) on every
> push to `main` (tag `latest`) and on `v*` tags. If the org's package visibility is private, make the
> `khandaq-api` / `khandaq-web` packages readable by your CapRover host (or add a registry credential),
> otherwise the pull will 403.
