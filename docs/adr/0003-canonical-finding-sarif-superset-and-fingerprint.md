# ADR-0003: Canonical finding is a SARIF superset; dedup by a stable fingerprint

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Every tool emits findings in its own format; none emits a shared model, few emit SARIF, and none
emits MITRE ATLAS IDs natively. For Khandaq to deduplicate across tools, assign comparable severity,
map to frameworks and report, there must be one canonical finding shape and a deterministic way to
tell when two findings are "the same issue".

## Decision

- **Canonical schema is a superset of SARIF 2.1.0**, with AI-specific data under an `x-khandaq`
  property (phase, framework mappings, evidence refs, dedup links, status). SARIF gives
  interoperability with existing security tooling and a well-specified `locations`/`result` model; the
  extension carries what SARIF lacks. The JSON Schema is the source of truth
  (`core/khandaq-core/schema/finding.schema.json`) and adapter output is validated against it.
- **Dedup uses a stable fingerprint:** `sha256` over a normalised tuple of {rule family, target,
  canonicalised location, salient request shape}. The *same* issue found by two tools, or by one tool
  across runs, produces the same fingerprint and collapses to one canonical finding; the others are
  linked via `dedup_of`, and their source tools and evidence are merged onto the canonical one.
- Fingerprinting and dedup live in the **Rust core** (`fingerprint`, `dedup`) with property tests for
  stability (same input → same hash; irrelevant reordering → same hash).

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Invent a bespoke schema | Exactly our needs | No interop; reinvents SARIF | SARIF superset gets interop for free |
| Pure SARIF, no extension | Max interop | No place for ATLAS/phase/evidence/dedup | Superset keeps interop and adds what we need |
| Dedup by tool-native ids | Easy | Different per tool; no cross-tool collapse | Defeats the purpose |
| Fuzzy/LLM dedup | Catches near-duplicates | Non-deterministic, costly, hard to test | Deterministic fingerprint first; revisit fuzzy later |

## Consequences

- Reports can say "3 high" instead of "17 raw results", and a client sees one issue with the evidence
  from every tool that found it.
- The normalisation quality depends on each adapter's mapping; adapters carry a documented rule→schema
  mapping and a contract test.
- Fingerprint design must be versioned (`schema: khandaq.finding/1`); a change to the fingerprint
  recipe is a schema version bump with a migration note.
- **Amended by ADR-0013 (2026-10-03):** the identity is {rule id, or a shared weakness from an
  explicit equivalence table; target; canonical location}. Framework mappings are no longer part of
  it. Schema id `khandaq.finding/2`, migration `0004_fingerprint_v2`.
