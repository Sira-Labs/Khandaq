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
# 1. Render with your web console's HTTPS origin (no trailing path)
python3 deploy/keycloak/render.py https://khandaq.siralabs.org > /tmp/khandaq-realm.json

# 2. Import into Keycloak — either:
#    (a) Admin console → Realm settings → Partial import → upload the file, or
#    (b) on first boot of a fresh Keycloak:
#        kc.sh import --file /tmp/khandaq-realm.json
```

Staging and production each import their own copy with their own origin (and their own secrets).

## After import — set in the admin console

1. **`khandaq-api` client secret** → put it in the API/worker env as `KHANDAQ_OIDC_CLIENT_SECRET`
   (and in the one-click form field).
2. **Google** and **GitHub** identity providers → fill in each `clientId`/`clientSecret`, and set the
   redirect/callback URL each requires:
   - Google OAuth client redirect: `https://<keycloak>/realms/khandaq/broker/google/endpoint`
   - GitHub OAuth app callback: `https://<keycloak>/realms/khandaq/broker/github/endpoint`
3. Confirm the client **redirect URI** `https://<your web origin>/api/auth/callback` matches
   `KHANDAQ_PUBLIC_URL`, and the **back-channel logout** URL
   `https://<your web origin>/api/auth/backchannel-logout`.

`KHANDAQ_OIDC_ISSUER` is then `https://<keycloak>/realms/khandaq`.

See `deploy/caprover.md` §5 for where this fits in the server setup, and the one-click app
(`deploy/caprover/one-click/`) which asks for the issuer and client secret this realm produces.
