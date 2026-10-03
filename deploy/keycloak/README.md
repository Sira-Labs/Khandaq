# Keycloak realm for Khandaq

`khandaq-realm.template.json` is a Keycloak realm export that sets up sign-in for Khandaq exactly as the
architecture requires (ADR-0005): a confidential **`khandaq-api`** OIDC client (Authorization Code +
PKCE, back-channel logout), **Google** and **GitHub** brokers, **passkeys**, and a brokered browser
flow (SSO cookie → identity-provider redirect → passkey; **no passwords**). New users are created or
linked by verified email with no review page.

**It contains no secrets.** The Google/GitHub client secrets and the `khandaq-api` client secret are
`set-in-admin-console` placeholders you fill in after import.

## Import

Use the **ready-made file** for the environment; it imports as it is, no rendering needed:

| Environment | File | Keycloak | `KHANDAQ_OIDC_ISSUER` |
|---|---|---|---|
| Staging | [`khandaq-realm-staging.json`](khandaq-realm-staging.json) (for `https://khandaq-stg.siralabs.org`) | the shared Keycloak `miftachun.apps.data-and-ai-dude.ch`, next to the `tabayyun` and `sahifa` realms | `https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq` |
| Production | [`khandaq-realm-production.json`](khandaq-realm-production.json) (for `https://khandaq.siralabs.org`) | production's own Keycloak | `https://<prod keycloak>/realms/khandaq` |

1. Download the file (GitHub → the file → *Download raw file*).
2. Keycloak admin console → realm drop-down (top left) → **Create realm** → *Resource file*:
   the downloaded file → **Create**. The realm is called `khandaq`.
3. Check: `https://<keycloak>/realms/khandaq/.well-known/openid-configuration` answers JSON
   instead of 404.

> **Do not import `khandaq-realm.template.json`.** It holds a `__PUBLIC_URL__` placeholder that
> Keycloak refuses: the admin console says *"unknown_error"* (the server log: *"Invalid client
> khandaq-api: Backchannel logout URL is not a valid URL; Root URL is not a valid URL"*) and no realm
> is created. Both ready-made files were imported into Keycloak 26.4 to check them.

> **Use _Create realm_ (full import), not _Realm settings → Partial import_.** This realm rebinds the
> browser flow to `khandaq browser` and defines custom passkey/broker flows. Partial import only
> brings in clients, roles, identity providers and scopes — it skips `authenticationFlows`,
> `authenticatorConfig` and the `browserFlow`/`firstBrokerLoginFlow` bindings — so the realm comes up
> broken. Full import creates everything in one step.

For any other origin (a test install, a new domain), render the template yourself:

```bash
python3 deploy/keycloak/render.py https://khandaq.example.org > khandaq-realm.json
# or, on first boot of a fresh Keycloak: kc.sh import --file khandaq-realm.json
```

After changing the template, run `python3 deploy/keycloak/render.py --all` to rewrite the two
ready-made files; a test (`api/tests/test_keycloak_realm.py`) fails while they are out of sync.

## After import — set in the admin console

1. **`khandaq-api` client secret** → put it in the **API** app's env as `KHANDAQ_OIDC_CLIENT_SECRET`
   (and in the one-click form field). The worker does not need it and should not have it.
2. **Google** and **GitHub** identity providers → fill in each `clientId`/`clientSecret`, and set the
   redirect/callback URL each requires:
   - Google OAuth client redirect: `https://<keycloak>/realms/khandaq/broker/google/endpoint`
   - GitHub OAuth app callback: `https://<keycloak>/realms/khandaq/broker/github/endpoint`

   On staging, `<keycloak>` is `miftachun.apps.data-and-ai-dude.ch`. Tabayyun and Sahifa use their
   own OAuth clients on the same Keycloak; Khandaq needs its own as well, because each broker
   endpoint names its realm.
3. Confirm the client **redirect URI** is exactly `KHANDAQ_PUBLIC_URL` + `/api/auth/callback` (e.g.
   `https://khandaq-stg.siralabs.org/api/auth/callback` on staging). A different host — the
   CapRover default `…-web.<root domain>`, or a missing `-stg` — makes Keycloak answer
   *"Invalid parameter: redirect_uri"*.
4. The client ID stays **`khandaq-api`** on every environment: it names the OIDC client in this realm,
   not the CapRover app (which may be `khandaq-stg-api`).

`KHANDAQ_OIDC_ISSUER` is then `https://<keycloak>/realms/khandaq` — on staging
`https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq`. Use the public URL, never a CapRover
internal name: the API checks that the issuer in the ID token (what browsers see) matches.

See `deploy/caprover.md` §5 for where this fits in the server setup, and the one-click app
(`deploy/caprover/one-click/`) which asks for the issuer and client secret this realm produces.
