# ADR-0007: Evidence is append-only and hash-chained; signing is optional

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

A red-team finding is only as good as its proof. The prompts, responses and artefacts behind a finding
must be captured, bound to the engagement and run, and made **tamper-evident**, because a client, an
auditor, or a dispute may rely on them long after the engagement. We need integrity that is verifiable
without trusting the Khandaq instance that produced it.

## Decision

- **Append-only evidence store.** Artefacts are written once to the object store (S3/RustFS),
  encrypted at rest, addressed by content hash, and never mutated or deleted by the application.
- **Hash-chained ledger.** Each `LedgerEntry` records the evidence hash and the hash of the previous
  entry, forming a chain per engagement. Anyone can recompute the chain and detect tampering or
  deletion. The chain **root** can be recomputed at any time and is **pinned into every report**.
- **Optional Sigstore signing.** An engagement's evidence bundle (the ledger root + manifest) can be
  signed with Sigstore so an external party verifies integrity and origin without trusting the
  instance. Signing is off by default (works air-gapped) and on by configuration.
- The ledger lives in the **Rust core** (`ledger`): `append`, `verify`, `root`, `sign`. It exposes no
  mutate/delete. A broken or unverifiable chain is a reported, high-severity condition.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Plain files in a folder | Trivial | No integrity, easily altered | Not defensible |
| Database rows, app-enforced immutability | Easy | App bug or DBA can alter silently | Hash chain detects alteration |
| Full blockchain / external notary | Strong | Heavy; network dependency; against self-host/air-gap | Hash chain + optional Sigstore is enough |
| **Append-only + hash chain + optional Sigstore (chosen)** | Verifiable, self-host & air-gap friendly, optional external trust | Must never expose mutate/delete | Accepted |

## Consequences

- The ledger API is deliberately missing mutate/delete; CodeRabbit path-instructions and CODEOWNERS
  guard it; property tests prove chain verification catches tampering.
- Reports pin the ledger root, so a report is bound to the exact evidence it cites.
- Retention/deletion for data-protection reasons is handled at the engagement level (closing/exporting
  then destroying an engagement's store), not by editing the ledger — documented in `deploy/`.
