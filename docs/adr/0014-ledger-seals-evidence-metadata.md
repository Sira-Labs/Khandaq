# ADR-0014: The ledger seals each evidence row's metadata, not just its content hash

- **Status:** Accepted (2026-10-03)
- **Date:** 2026-10-03
- **Deciders:** project owner (open decision raised by the 2026-10-02 code review)

## Context

ADR-0007 chains each ledger entry over `evidence_hash`, and until now that was the artefact's
`sha256` alone. The evidence row's other columns were outside the chain:

- `object_key` (where the artefact is);
- `run_id` (which run produced it);
- `kind`, `bytes` and `redacted`.

Migration 0003 made `evidence` append-only by trigger, which stops the application from editing
them. It does not stop a database owner or DBA, who can disable the trigger and:

- point sealed evidence at another object;
- move it to another run;
- mark it redacted.

None of that breaks verification, so the chain proved the bytes were unchanged but not which
finding, run or object they belonged to. ADR-0007's own threat model ("an app bug or DBA can alter
silently") is exactly this case.

## Decision

- **Entry format 2.** A format-2 entry's `evidence_hash` is the core's `evidence_record_hash`:
  `sha256` over the canonical (sorted-key, compact) JSON of
  `{schema: "khandaq.evidence/2", id, engagement_id, run_id, kind, object_key, sha256, bytes, redacted}`.
  The record type refuses unknown and missing fields, so a caller cannot believe it bound a field
  it did not.
- **The format is bound into the entry hash.** Format 2 computes
  `entry_hash = sha256("khandaq.ledger/2" ‖ seq ‖ evidence_hash ‖ prev_hash)` (NUL-separated).
  Format 1 keeps its untagged recipe.
  - Without the tag, an attacker could set an entry's format to 1 and write the old record hash
    into `evidence.sha256`, and verification would pass with any metadata.
  - With the tag, relabelling the format breaks the entry hash.
- **Formats never go down.** `verify` refuses a chain whose formats decrease, and refuses an
  unknown format.
- **Existing chains stay valid.** `ledger_entries.format` (migration 0005) marks every existing
  entry as format 1, which is what it sealed. New entries are format 2, so an engagement's chain
  may be 1…1 2…2.
  - Downgrading 0005 is refused once a format-2 entry exists.
  - No existing entry is rewritten; that would break the pinned roots in issued reports.
- `created_at` is not sealed. It is not evidence about the artefact, and its text form is not
  canonical across drivers.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Keep sha256-only, rely on triggers and DB privileges | No change | A DBA can relabel or move evidence silently | The ledger exists to not trust the DB |
| Re-seal all existing chains under the new formula | One format everywhere | Changes every root already pinned in a report | Breaks issued reports |
| Per-entry format without a tag in the entry hash | Simpler | Downgrade attack: re-read a v2 entry as v1 | Defeats the purpose |
| **Tagged format 2, format 1 kept for old entries (chosen)** | Old chains verify, new evidence fully bound | Two formats to verify | Accepted |

## Consequences

- An external verifier recomputes a format-2 `evidence_hash` from the evidence metadata (the
  recipe above), and the entry hash with the format tag.
- A future change to the record or the entry hash is a new format number, never an edit. Golden
  tests pin both recipes.
- Evidence sealed before 0005 keeps its weaker binding. Re-sealing it would need a deliberate,
  audited re-attestation flow, which is out of scope here.
