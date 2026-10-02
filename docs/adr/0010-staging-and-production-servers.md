# ADR-0010: Separate staging and production CapRover servers; promote tested digests

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner (Sīra family decision, mirrors Tabayyun ADR-0016 / Arqam ADR-0020)

## Context

The Sīra family runs on Hetzner CapRover servers with a staging/tools host and a production host, and
deploys by **promoting a tested image digest** from staging to production rather than redeploying
`main` to production directly. Khandaq handles especially sensitive data (engagement scope, captured
evidence, client findings), so it must follow the same discipline — arguably more strictly.

## Decision

- **Two CapRover servers.** Staging/tools runs `khandaq-stg-*` apps at `khandaq-stg.siralabs.org` with
  test data only. Production runs `khandaq-*` apps at `khandaq.siralabs.org` with real engagement data,
  its own object store, and Keycloak. (Amended 2026-10-02: staging apps were first written as
  `khandaq-*-stg`; the CapRover one-click names apps `<app>-<role>`, so staging deployed as
  `khandaq-stg-api` etc. and the docs now follow that.)
- **Promotion, not rebuild.** `release.yml` builds and scans images once per commit and deploys `main`
  to staging; `promote.yml` deploys the **same digests** to production after the commit is on `main`,
  staging serves it, and the owner approves (a required reviewer on the `production` environment).
- **Separation of data and secrets.** Real engagement data and evidence live **only** on production.
  Staging and production have independent secrets (DB, session, object-store keys, OIDC clients,
  CapRover app tokens, and the **evidence-encryption key**).
- **Backups** of production Postgres (continuous WAL + nightly dump) and a versioned copy of the
  evidence object store, encrypted, to a second location; restore drills into a throwaway DB on
  production, never into staging.
- Production allows SSH by key only; firewall opens 80/443/22; CapRover dashboard uses a strong
  password and 2FA.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| One server | Cheap | Shared failure; test data beside client evidence | Unacceptable for this data |
| Deploy `main` straight to prod | No second server | No tested artefact before prod | Promotion is the point |
| Managed Postgres | Less ops | Cost; another subprocessor for sensitive data | Revisit at scale |
| **Two servers + promote digests (chosen)** | Tested artefact; data/secret separation; family-consistent | A second server to run | Accepted |

## Consequences

- `deploy/caprover.md` describes both servers, the GitHub environments/secrets, egress policy for
  adapter containers, and the backup/restore requirements.
- Because evidence is especially sensitive, the production object store is never shared with staging and
  its encryption key is production-only.
- Owner tasks (tracked in `TASKS.md`): order/confirm the production server, set the environments and tag
  ruleset, provision Keycloak realm, choose the backup location and the KMS/key story.
