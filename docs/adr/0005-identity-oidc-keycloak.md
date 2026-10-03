# ADR-0005: Identity via OIDC (Keycloak), BFF session, API tokens for automation

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Khandaq manages sensitive engagements and must authenticate operators and analysts, support
per-engagement roles, and allow CLI/CI automation. The Sīra family already runs Keycloak for Tabayyun
and Arqam, so reusing it keeps one identity story across projects.

## Decision

- **OIDC** (Authorization Code + PKCE) against **Keycloak** as the default IdP (Google, GitHub,
  passkeys as upstream brokers). A single-user self-host may run without Keycloak via a local admin
  bootstrap, but production requires an IdP.
- **Backend-for-frontend (BFF):** the browser holds only a `__Host-` server-side session cookie; no
  tokens in the browser; CSRF header check on state-changing requests; back-channel logout.
- **API tokens** (scoped, revocable, audited) for the `khandaq` CLI and CI pipelines, distinct from
  user sessions, each tied to a user and carrying that user's engagement roles.
- Authorisation is enforced server-side by an `authorize()` dependency (org roles + per-engagement
  roles), per `docs/architecture/04-engagement-scope-and-authz.md`.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Roll our own auth | No dependency | Security-critical, easy to get wrong | Never for an auth system |
| Tokens in the browser (SPA holds JWT) | Simpler SPA | XSS token theft; weaker logout | BFF is safer |
| A different IdP (Zitadel/Authentik) | Fine alternatives | Family already runs Keycloak | Consistency wins; still OIDC-standard so swappable |

## Consequences

- Reuses family Keycloak operational knowledge and realm patterns (see Tabayyun/Arqam).
- Production refuses to start without the OIDC settings (fail closed).
- API tokens are first-class in the audit log (actions record the token id).
- Users are keyed by the IdP account (`iss`, `sub`), not by email (2026-10-03, spec 008 behaviour
  9): email is display and allow-list only, and an email linked to one IdP account is refused for
  any other.
