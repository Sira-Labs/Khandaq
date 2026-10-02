# ADR-0004: Normalised five-level severity, mapped per adapter

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Tools disagree on severity: garak reports a pass/fail rate per probe, promptfoo has its own grading,
scanners emit CVSS-like scores. A unified findings model needs comparable severities so a report and a
campaign diff mean the same thing across tools.

## Decision

A single normalised scale: **info · low · medium · high · critical**. Each adapter declares, in its
`adapter.yaml`, a documented mapping from its tool's native severity/score to this scale; the Rust
`severity` module applies it. When dedup merges findings from several tools, the canonical severity is
the **maximum** of the contributors, and the contributing native severities are retained on the
finding for transparency. Severity may be adjusted by engagement-level policy (e.g. a target marked
high-value raises the floor), recorded as an explicit, audited override — never silently.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Keep each tool's native severity | No mapping work | Not comparable; breaks dedup/reporting | Defeats unification |
| Adopt CVSS | Familiar, numeric | Ill-fitting for LLM findings; false precision | Over-engineered for now |
| **Five-level + per-adapter map (chosen)** | Comparable, simple, transparent | Mapping tables to maintain | Accepted |

## Consequences

- Every adapter must ship and justify its severity table; it is reviewed with the adapter.
- The "max on merge" rule is simple and defensible; edge cases (a tool that over-reports critical) are
  handled by fixing that adapter's table, not by special-casing the core.
- Overrides are auditable, so a client can see why a finding was raised or lowered.
