# ADR-0002: Licence is Apache-2.0

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Khandaq needs a licence that permits self-hosting and commercial consulting use, is familiar to
security teams, and is compatible with orchestrating third-party tools that carry their own licences.
The Sīra family (Thawr, Tabayyun) standardised on Apache-2.0.

## Decision

Apache-2.0 for all original code in this repository. Khandaq **does not vendor or relicense** the
upstream tools it orchestrates; each adapter records the upstream tool's own licence in its
`adapter.yaml`, and the tools are pulled as their own container images. Adapters for tools under
incompatible licences (e.g. non-commercial or strong copyleft that would encumber the suite) are
flagged at proposal time and, where needed, kept as optional, separately-distributed images rather
than bundled.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| MIT | Simplest | No explicit patent grant | Apache's patent grant matters for a security tool |
| AGPL | Forces sharing of modifications | Deters commercial/self-host adopters; friction with consulting use | Against the adoption goal |
| Business Source / source-available | Monetisation control | Not open source; against family norms | No |
| **Apache-2.0** | Patent grant, permissive, familiar, family-consistent | None material | Chosen |

## Consequences

- `LICENSE` (Apache-2.0) and `NOTICE` are in the repo root; source headers are not required but the
  NOTICE names the project and the third-party orchestration relationship.
- Adapter manifests must state the upstream licence; the adapter proposal template asks for it, and a
  licence that would encumber the suite is caught in review.
