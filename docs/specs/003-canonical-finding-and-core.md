# Spec 003 — Canonical finding schema, fingerprint, dedup, severity, mapping (Rust core)

Sprint 2, story S2-1. Depends on: none (parallel to 001/002). Packages: `core/` (khandaq-core,
khandaq-py), consumed by `api/`.

## Goal

The Rust core defines the canonical finding (a SARIF superset), validates arbitrary adapter output
against its JSON Schema, computes a stable fingerprint, deduplicates a set of findings, applies
per-adapter severity mapping, and applies the framework mapping tables. Exposed as a `khandaq_core`
Python wheel and a `khandaq-core` CLI. This is the data spine every adapter and report depends on.

## User story

As the platform, I want one finding model with deterministic dedup and framework mapping so that
results from different tools add up to one defensible report.

## Interface

Rust library (`khandaq-core`) and Python (`khandaq_core`):

- `validate(value) -> Result<Finding, SchemaError>` — against `schema/finding.schema.json` (ADR-0003).
- `fingerprint(&Finding) -> String` — `sha256:…` over the normalised {rule family, target,
  canonical location, salient request shape}; stable and order-insensitive.
- `dedup(Vec<Finding>) -> DedupResult` — groups by fingerprint; one `canonical` per group with the rest
  linked `dedup_of`; merges `source` tools and `evidence` refs onto the canonical.
- `severity_map(&Finding, &AdapterSeverityTable) -> Severity` — native → `info|low|medium|high|critical`;
  on a merge the canonical severity is the max of contributors.
- `map_frameworks(&Finding, &Mappings) -> Vec<Mapping>` — ATLAS, OWASP LLM 2025 + 2026, ASI, NIST,
  EU AI Act (ADR-0012).
- `navigator_layer(&[Finding]) -> NavigatorLayer` — MITRE ATLAS Navigator export.

CLI: `khandaq-core validate <file>`, `… normalize <raw> --adapter garak`, `… navigator <findings>`.

## Behaviour

1. `validate` rejects output that is not a superset-valid finding with a precise error (used by every
   adapter's contract test).
2. `fingerprint` is deterministic: same logical finding → same hash; reordering irrelevant fields →
   same hash; a different target or rule family → different hash.
3. `dedup` collapses the same issue found by several tools into one canonical finding carrying every
   source and all evidence refs; it never drops evidence.
4. `severity_map` applies the adapter's documented table; the merge rule is max (ADR-0004).
5. `map_frameworks` returns all applicable IDs across frameworks and both OWASP years; an unmapped rule
   yields an explicit "unmapped" marker (so curation gaps are visible, not silent).

## Acceptance criteria

- [x] `finding.schema.json` exists; `validate` accepts a valid finding and rejects malformed ones.
- [x] Fingerprint stability and order-insensitivity; distinctness on target/rule change (test).
- [x] `dedup` merges a crafted multi-tool set into the expected canonical set with merged evidence.
- [x] Severity max-on-merge is proven; mapping fixtures map known rules to expected framework IDs.
- [x] The `khandaq_core` wheel imports in Python and round-trips a finding; the `khandaq-core` CLI runs.

> Notes (recorded per CLAUDE.md): `validate` is the **typed Rust model** (serde) that mirrors the
> published `finding.schema.json` — this keeps validation fast and dependency-free; the schema file is
> the external contract adapters document against. The fingerprint identity is the **set of framework
> mapping ids** (so two tools mapping to the same id collapse) + target + canonical location, with
> `rule_id` as the fallback identity when a finding has no mappings yet. The Python binding is
> JSON-in/JSON-out (strings). Dedup records contributing tools in `x-khandaq.also_found_by`; DB-side
> `dedup_of` id-linking lands with persistence of findings (spec 005).

## Test cases

Rust unit + property (`core/khandaq-core/tests/`): schema validation, fingerprint properties, dedup
merge, severity max, mapping fixtures, navigator layer shape. Python (`core/khandaq-py/tests/`): wheel
import + round-trip.

## Out of scope

The ledger (spec 004); persisting findings (wired in spec 005/007); exhaustive mapping coverage (the
tables grow over time; this spec lands the mechanism + seed entries for the R1 adapters).
