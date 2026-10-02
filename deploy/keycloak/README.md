# Keycloak realm for Khandaq

`khandaq-realm.json` is a Keycloak realm export that sets up sign-in for Khandaq exactly as the
architecture requires (ADR-0005): a confidential **`khandaq-api`** OIDC client (Authorization Code +
PKCE, back-channel logout), **Google** and **GitHub** brokers, **passkeys**, and a brokered browser
flow (SSO cookie → identity-provider redirect → passkey; **no passwords**). New users are created or
linked by verified email with no review page.

**It contains no secrets.** The Google/GitHub client secrets and the `khandaq-api` client secret are
`set-in-admin-console` placeholders you fill in after import.

## Import

The export has a `__PUBLIC_URL__` placeholder for your install's origin. Render it, then import:

```bash
# 1. Render with THIS environment's web-console origin (no trailing path) — the domain attached
#    to the web app, identical to KHANDAQ_PUBLIC_URL on the api:
python3 deploy/keycloak/render.py https://khandaq-stg.siralabs.org > khandaq-realm.json   # staging
python3 deploy/keycloak/render.py https://khandaq.siralabs.org > khandaq-realm.json       # production

# 2. Import into Keycloak as a FULL realm import — either:
#    (a) Admin console → realm drop-down → Create realm → Resource file: the rendered
#        file → Create, or
#    (b) on first boot of a fresh Keycloak:
#        kc.sh import --file khandaq-realm.json
```

> **Use _Create realm_ (full import), not _Realm settings → Partial import_.** This realm rebinds the
> browser flow to `khandaq browser` and defines custom passkey/broker flows. Partial import only
> brings in clients, roles, identity providers and scopes — it skips `authenticationFlows`,
> `authenticatorConfig` and the `browserFlow`/`firstBrokerLoginFlow` bindings — so the realm comes up
> broken ("realm could not be created" / no sign-in). Full import creates everything in one step.

Staging and production each import their own copy with their own origin (and their own secrets).

## After import — set in the admin console

1. **`khandaq-api` client secret** → put it in the **API** app's env as `KHANDAQ_OIDC_CLIENT_SECRET`
   (and in the one-click form field). The worker does not need it and should not have it.
2. **Google** and **GitHub** identity providers → fill in each `clientId`/`clientSecret`, and set the
   redirect/callback URL each requires:
   - Google OAuth client redirect: `https://<keycloak>/realms/khandaq/broker/google/endpoint`
   - GitHub OAuth app callback: `https://<keycloak>/realms/khandaq/broker/github/endpoint`
3. Confirm the client **redirect URI** is exactly `KHANDAQ_PUBLIC_URL` + `/api/auth/callback` (e.g.
   `https://khandaq-stg.siralabs.org/api/auth/callback` on staging). A different host — the
   CapRover default `…-web.<root domain>`, or a missing `-stg` — makes Keycloak answer
   *"Invalid parameter: redirect_uri"*.
4. The client ID stays **`khandaq-api`** on every environment: it names the OIDC client in this realm,
   not the CapRover app (which may be `khandaq-stg-api`).

`KHANDAQ_OIDC_ISSUER` is then `https://<keycloak>/realms/khandaq`.

See `deploy/caprover.md` §5 for where this fits in the server setup, and the one-click app
(`deploy/caprover/one-click/`) which asks for the issuer and client secret this realm produces.
