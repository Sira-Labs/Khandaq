# Spec 008 — OIDC (Keycloak) BFF + real roles

Sprint 4, story S4-4. Depends on: 001, 002. Implements: ADR-0005. Packages: `api/` (auth).

## Goal

Real authentication replaces the development stub. A browser logs in through an OIDC IdP (Keycloak,
Authorization Code + PKCE); the server holds a session and the browser holds only a `__Host-` session
cookie (backend-for-frontend — no tokens in the browser). State-changing requests carry a CSRF header.
Automation authenticates with revocable, audited **API tokens** (bearer). In production the app fails
closed without the OIDC settings, and the dev header stub is refused there (as it is today) — but now
there is a real path, so production is usable. The development header stub stays available outside prod
so the existing authz tests and the local demo keep working.

## User story

As an operator, I log in via our Keycloak so that my identity and per-engagement roles are real and
every privileged action is attributable; as a CI pipeline, I use a scoped API token so that automated
runs are authenticated and audited without a browser.

## Interface

New/enforced settings (env, `KHANDAQ_` prefix): `oidc_issuer`, `oidc_client_id` (default
`khandaq-api`), `oidc_client_secret`, `public_url` (base URL, for the redirect URI),
`session_secret` (already present), `session_ttl_hours` (default `12`). In **prod**,
`validate_runtime()` additionally requires `oidc_issuer`, `oidc_client_secret` and `public_url` **for
the `api` role only**. (Corrected 2026-10-02: the first version applied this to every role, so the
worker — which calls `validate_runtime()` but serves no logins and is deployed without the client
secret — would refuse to start. The worker must not need the OIDC secret: least privilege.)

Database — new table `sessions` (migration `0002_sessions`):
`id` (`ses_…` pk), `user_id` (FK users), `csrf` (text), `created_at`, `expires_at` (timestamptz),
`revoked_at` (nullable).

Routes (prefix `/api/auth`):
- `GET /login?next=<relative-path>` → `307` to the IdP authorization endpoint (Authorization Code +
  PKCE). Sets a short-lived signed (HMAC over `session_secret`) `khandaq_login` cookie carrying
  `state`, `nonce`, PKCE `verifier`, and the sanitised `next`.
- `GET /callback?code&state` → verifies the login cookie and `state`, exchanges the code at the token
  endpoint with the PKCE verifier, validates the `id_token` (signature via JWKS, `iss`, `aud`, `exp`,
  `nonce`), upserts the `User` by email, creates a `sessions` row, sets the `__Host-khandaq_session`
  cookie, and `307`-redirects to `next` (default `/`). Bad/absent state or a failed exchange → `400`.
- `POST /logout` → revokes the current session row and clears the cookie (`200`, `{status}`). CSRF
  header required (it is a state-changing request).
- `GET /me` → `{id, email, display_name, org_role, csrf_token, auth}` where `auth` is
  `session|token|dev`.
- `POST /tokens` `{name}` → `{id, name, token}` — the plaintext token is shown **once**; only its
  sha256 hash is stored. `GET /tokens` lists the caller's tokens (no secrets). `DELETE /tokens/{id}`
  revokes one (`204`).

`current_user` resolution order: (1) `Authorization: Bearer <token>` → sha256 lookup in `api_tokens`
(not revoked) → user; (2) `__Host-khandaq_session` cookie → live `sessions` row → user; (3) the dev
header stub, **non-prod only**. If none resolve: `401` (prod no longer returns `501`).

## Behaviour

1. **BFF, fail closed.** No OIDC tokens are ever sent to the browser. The session cookie is
   `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, `__Host-` prefixed. Prod refuses to start without
   `oidc_issuer`/`oidc_client_secret`/`public_url` (invariant: no insecure prod boot).
2. **id_token validation.** The callback validates the token's signature against the issuer's JWKS and
   checks `iss`, `aud` (contains the client id), `exp`, and the `nonce` from the login cookie. Any
   failure → `400`, no session created.
3. **CSRF.** For a session-authenticated request with an unsafe method (`POST/PUT/PATCH/DELETE`),
   `X-Khandaq-CSRF` must equal the session's `csrf`, else `403`. Bearer-token requests carry no
   ambient cookie and are exempt. The dev stub is exempt (non-prod only).
4. **API tokens.** Stored as sha256 hash only; plaintext returned once at creation. A token carries
   its user's org/engagement roles. Revoked (`revoked_at` set) → `401`. `last_used_at` is updated on
   use. Invariant (audit): `auth.login`, `auth.logout`, `token.create`, `token.revoke` are audited;
   token-authenticated privileged actions record `actor_token_id`.
5. **Upsert.** The first user to log in whose email equals `admin_email` is created `org_role=admin`;
   others `member`. An existing user keeps their role (login never escalates/downgrades).
6. **Who may sign in** (added 2026-10-02 after a code review). The realm brokers *any* Google or
   GitHub account, so the callback admits only an `email_verified=true` address that is
   `admin_email` or on `KHANDAQ_ALLOWED_EMAILS` (comma-separated, case-insensitive; empty = admin
   only). Anyone else gets no user row and no session, is redirected to `/?signin=denied`, and is
   audited as `auth.denied`. The list is re-checked on every session- and token-authenticated
   request, so removing an address revokes access at once. Users stay keyed by email; keying by
   (`iss`, `sub`) is a follow-up.
7. **Strict environment.** `KHANDAQ_ENV` must be `dev`, `test` or `prod`; any other value refuses to
   start, because every non-prod value enables the dev login stub. In prod only the `__Host-` session
   cookie is read.
8. **Token attribution.** The token id is carried on the request's `User` (one DB session per
   request) and read by `audit.record`. The first version used a `ContextVar` set in the sync
   `current_user` dependency, which FastAPI runs in a threadpool on a copied context, so endpoints
   never saw it and token actions were recorded without `actor_token_id`.

## Acceptance criteria

- [x] `GET /login` returns `307` to the issuer's authorization endpoint with `code_challenge`,
      `code_challenge_method=S256`, `state`, and sets the signed `khandaq_login` cookie.
- [x] `GET /callback` with a stubbed IdP (injected client) returning valid claims creates/updates the
      user, sets `__Host-khandaq_session`, and redirects to `next`; a tampered/absent state → `400`.
- [x] `GET /me` over a session cookie returns the user and a `csrf_token` with `auth="session"`.
- [x] A session-authenticated `POST` without `X-Khandaq-CSRF` → `403`; with the correct header → `2xx`.
- [x] `POST /tokens` returns a plaintext token once; using it as `Bearer` authenticates (`/me`
      `auth="token"`); after `DELETE /tokens/{id}` the same token → `401`.
- [x] With `env=prod` and no session/token, a protected route returns `401` (not `501`); and
      `validate_runtime()` raises without the OIDC settings.

## Test cases

Integration (`api/tests/test_auth.py`): an injected fake OIDC client (via `app.dependency_overrides`)
returns canned token/claims so the full callback→session path runs without a live IdP. Covers: login
redirect + login cookie; callback→session + `/me`; tampered state → 400; CSRF enforced then satisfied;
API-token create→use→revoke; logout clears + revokes; prod protected route → 401 with no creds.
Unit (`api/tests/test_settings.py`): `validate_runtime()` requires the OIDC settings in prod.
Security: the negative tests (missing CSRF → 403; revoked token → 401; prod no-creds → 401; tampered
state → 400) prove the BFF/CSRF/token invariants.

## Out of scope

Live Keycloak end-to-end (deploy-verified; the realm export ships at `deploy/keycloak/`). IdP
brokering config and passkeys (upstream Keycloak concern). Accepting IdP-initiated back-channel logout
tokens, and the front-channel IdP `end_session` redirect (logout is local — the session row is
revoked and the cookie cleared), and fine-grained per-token scopes beyond the user's roles (R2). Refresh-token rotation /
silent renewal (sessions expire; the user logs in again).
