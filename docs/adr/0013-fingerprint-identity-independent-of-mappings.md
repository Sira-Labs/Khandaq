# ADR-0013: Fingerprint identity independent of framework mappings

- **Status:** Proposed
- **Date:** 2026-10-02
- **Deciders:** project owner (open decision raised by the 2026-10-02 code review)

## Context

ADR-0003 fixes the fingerprint as `sha256` over a normalised identity. The implementation
(`khandaq-core/src/fingerprint.rs`) hashes three things:

- the **set of framework-mapping ids** on the finding, falling back to `rule:<rule_id>` only when it
  has none;
- `target_ref`;
- the serialised `locations`.

The code review found that the mapping-based identity works against what ADR-0003 wants:

1. **Mappings are mutable data, so fingerprints drift.** ADR-0012 makes mappings versioned data that
   is expected to change: curation adds ids and a new OWASP edition adds a column. Any such change
   gives the *same* issue on the *same* target a new fingerprint. Cross-run dedup (spec 005: a
   partial unique index on the canonical fingerprint, with `dedup_of` links) then stops matching.
   Findings that were already triaged come back as new, open findings. The adapter fix that added
   OWASP LLM 2025 ids (PR #25) changes every garak, PyRIT and promptfoo fingerprint in this way.
   It is harmless today only because no adapter has executed against a live target yet: Docker
   execution is still a follow-up.
2. **Distinct issues can collapse.** Two different rules with the same mapping set, the same target
   and empty or equal locations get one fingerprint. Dedup keeps only one `rule_id`.
3. **The cross-tool merge it was meant to buy rarely happens.** Each adapter puts its own vocabulary
   in `locations`: a garak probe name, a PyRIT strategy, a promptfoo plugin id. Equal mapping sets
   from two tools therefore almost never share a location. In practice the identity is per tool
   anyway, while still paying the drift cost in (1).

## Decision (proposed)

Introduce **fingerprint v2**, which drops framework mappings from the identity entirely:

- The fingerprint becomes `sha256` over `{v: 2, weakness, target_ref, location}`.
- `weakness` is the finding's `rule_id`, unless a versioned **equivalence table** maps that rule id
  to a shared weakness key. For example, `garak.promptinject.*` and `pyrit.crescendo` could both map
  to `prompt-injection/direct`. The table is data, like ADR-0012 mappings. Changing it is an explicit,
  reviewed act that comes with a fingerprint migration note. It is not a side effect of mapping
  curation.
- Cross-tool collapse happens only through that table, and only when the canonical location is
  equal.
- Per ADR-0003, a recipe change is a schema version bump: `khandaq.finding/2`. An Alembic migration
  recomputes stored fingerprints from each finding's `body` and re-links `dedup_of` under the new
  recipe. That migration re-runs the duplicate merge that `0003_append_only` already performs.

Until this ADR is accepted, the v1 recipe stays unchanged. The 2026-10-02 core fixes deliberately
leave `fingerprint.rs` alone.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Keep v1 (mappings in identity) | No migration | Fingerprints drift with every mapping edit; distinct rules collide | The drift silently breaks cross-run dedup and triage carry-over |
| Freeze mappings per finding at first sight | Stable per finding | The same issue seen before and after a mapping edit still differs | Moves the drift problem rather than removing it |
| `rule_id` only, no equivalence table | Simplest, stable | Never merges across tools | Acceptable fallback; the table adds cross-tool merge back explicitly |
| Fuzzy/LLM dedup | Catches near-duplicates | Non-deterministic (ADR-0003) | Rejected in ADR-0003 |

## Consequences

- Mapping curation (ADR-0012) no longer moves fingerprints. Triage state survives mapping updates.
- Cross-tool merge becomes deliberate and reviewable, through the equivalence table, instead of
  accidental.
- This needs a `khandaq.finding/2` schema id, a fingerprint migration with a test that runs it over
  pre-migration data, and updates to spec 003 and spec 005.
- This is best accepted **before** any adapter runs against a live target. After that point, every
  stored fingerprint has to be migrated.
