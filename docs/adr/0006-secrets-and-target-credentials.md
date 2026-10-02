# ADR-0006: Secrets and target credentials are referenced, never stored in the clear

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Reaching a target often needs a credential (an API key for an LLM endpoint, a token for an MCP
server). Khandaq also holds its own secrets (session secret, DB and object-store credentials, OIDC
client secret). Captured evidence may itself contain sensitive text. Mishandling any of these is a
breach.

## Decision

- **Khandaq's own secrets** come from environment variables only; nothing is committed; production
  refuses placeholder values and fails to start without the required settings.
- **Target credentials** are stored encrypted at rest (envelope encryption with a key from the
  environment/KMS), referenced by id from a target, decrypted only in the control plane at launch time,
  injected into the adapter container as an ephemeral environment value for the single run, and never
  written to logs, URLs or the finding/evidence records.
- **Evidence** is encrypted at rest; secrets are redacted from raw tool output before it is shown in the
  UI, with the unredacted artefact available only to authorised roles.
- No secret or credential ever appears in an error message, audit entry, or exported report.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Store target creds plaintext in DB | Simple | Breach exposes client systems | Unacceptable |
| Require an external secrets manager always | Strong | Deployment friction for self-host | Support it, don't require it |
| **Encrypted-at-rest + env/KMS key (chosen)** | Safe, self-host-friendly | Key management to document | Accepted |

## Consequences

- A key-management section goes in `deploy/` (how to provide the encryption key; rotation).
- Tests and fixtures use synthetic credentials only; CI has a secret-scan step.
- Redaction is a core concern of the evidence path and has its own tests.
