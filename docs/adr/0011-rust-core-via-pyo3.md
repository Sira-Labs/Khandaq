# ADR-0011: Integrity-critical logic in a Rust core, exposed to Python via PyO3

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

The findings canonicalisation, fingerprinting, dedup, severity mapping, framework mapping and —
above all — the hash-chained evidence ledger are correctness- and integrity-critical and run over
potentially large result sets. The control plane is Python (FastAPI) for ecosystem reasons, but these
parts benefit from Rust's determinism, performance and memory safety. The family (Tabayyun) already
ships a Rust core as a PyO3 wheel successfully.

## Decision

Put the integrity-critical kernel in a **Rust workspace** (`core/`): `khandaq-core` (library),
`khandaq-cli` (offline binary), `khandaq-py` (PyO3 wheel `khandaq_core` the API imports). The API
calls the core for: validate-against-schema, fingerprint, dedup, severity, mapping, ledger
append/verify/root/sign, and campaign diff. The core is pure where possible, has unit + property
tests, and the ledger exposes no mutate/delete.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Pure Python core | Simplest; one language | Weaker determinism guarantees; slower on large sets; the ledger deserves stronger guarantees | Rust for the integrity-critical parts |
| Go core | Fast, simple | PyO3-style in-process binding is clumsier; family uses Rust | Consistency + PyO3 ergonomics |
| **Rust core via PyO3 (chosen)** | Safety, determinism, speed, offline CLI, family-consistent | Rust toolchain in the build | Accepted |

## Consequences

- Build needs a Rust toolchain; CI builds the wheel (`maturin`) and runs core tests; `uv` rebuilds the
  wheel when core sources change.
- The `khandaq-core` CLI allows offline/air-gapped verification of an evidence ledger and offline
  normalisation of tool output without the full control plane.
- The finding JSON Schema lives in the core and is the single source of truth adapters validate against.
