# Spec 020 — Framework mapping tables applied at ingest

Sprint 2 (carried), story S2-3. Depends on: 003, 005, 006, 009, 010. Packages: `core/`
(mappings, CLI, wheel), `api/` (runs, reports), `docs/`.

## Goal

ADR-0012 makes the framework cross-walk **versioned data in the core**, and reports and the
Navigator export are driven by it. Today the table has five seed rows whose keys do not match the
rule ids the adapters emit, its version metadata is never read, and the API never applies it. The
mappings stored on a finding come only from each adapter's hard-coded dict.

When this spec is done, the core table covers every rule family the R1 adapters and the built-in
`echo` adapter emit. The table carries a version and a source for every framework it uses, and it
matches a family's entry for every probe in that family. The API applies the table to every
finding at ingest, so a finding carries its adapter's ids plus the table's. A finding with neither
carries an explicit `unmapped` marker instead of nothing. Reports state which table versions they
were built with. A test fails if an adapter's own dict disagrees with the core table.

## User story

As an analyst, I export a report and every finding names its ATLAS, OWASP LLM (2025 and 2026) and
NIST AI RMF ids from one versioned table, and a rule nobody has mapped yet shows up as
`unmapped` instead of silently missing from the framework summary.

## Interface

- **Table** `core/khandaq-core/mappings/builtin.json`, schema `khandaq.mappings/1`:

  ```json
  {
    "schema": "khandaq.mappings/1",
    "versions": {"atlas": "v2026.09", "owasp-llm-2025": "2025", "...": "..."},
    "sources":  {"atlas": "https://atlas.mitre.org/", "...": "..."},
    "rules": {
      "garak.promptinject": {
        "mappings": [{"framework": "atlas", "id": "AML.T0051"}],
        "rationale": "why these ids"
      }
    }
  }
  ```

  A rule key is a rule-id **prefix**. A finding's `rule_id` matches a key when it equals the key or
  starts with the key followed by `.` or `:`. The **longest** matching key wins, so
  `garak.promptinject.hijackhatehumansmini` uses `garak.promptinject` and `promptfoo.harmful:hate`
  uses `promptfoo.harmful`. A bare tool key (`pyrit`, `promptfoo`) is that tool's default.
- **Core** (`khandaq-core`):
  - `Mappings::for_rule(rule_id)` — longest-prefix match as above.
  - `Mappings::versions()`, `Mappings::sources()`.
  - `merge_mappings(&Finding, &Mappings) -> Vec<Mapping>` — the finding's own ids plus the table's,
    sorted and de-duplicated. If both are empty, it returns `[{framework: "unmapped", id: rule_id}]`.
  - `map_frameworks` keeps its contract (table only, or the marker).
- **Wheel** (`khandaq_core`): `merge_mappings(finding_json) -> mappings_json` and
  `mapping_table() -> {"schema", "versions", "sources"}` as JSON.
- **CLI**: `khandaq-core normalize` applies `merge_mappings` to every finding, replacing the
  previous fill-only-when-empty behaviour.
- **API**: the run ingest path (`runs.py`) sets `x-khandaq.mappings` to `merge_mappings` before
  validation and dedup. `GET /report` gains `mapping_tables: {versions, sources}`, and the HTML
  report prints the versions under the framework summary.

## Behaviour

1. **Load.** The table is embedded at build time. A table that fails to parse, uses a framework with
   no version or no source, has an empty key, or has a rule with no mappings is a build-time test
   failure. It never reaches a release.
2. **Match.** Longest prefix on a `.` or `:` boundary. `garak.promptinjectx` does **not** match
   `garak.promptinject`. Matching is case-sensitive: rule ids are lower-cased by the adapters.
3. **Merge at ingest.** For each adapter finding, the stored mappings are the union of the
   adapter's ids and the table's ids. The union is sorted by `(framework, id)` with exact
   duplicates removed. The adapter's ids are kept, so a tool-specific id is never lost. The table
   fills the frameworks the adapter does not name, such as NIST AI RMF. A finding with neither
   gets the `unmapped` marker.
4. **No identity change.** Mappings are not part of the fingerprint (ADR-0013), so enriching them
   moves no fingerprint and no dedup decision. Findings stored before this spec keep their
   mappings. Nothing is rewritten in place.
5. **Reports.** `summary.by_framework` counts the merged ids, so an `unmapped:<rule>` entry shows
   the curation gap. `mapping_tables` names the versions and sources the counts refer to. The report
   pin, export audit and verification are unchanged.
6. **Drift guard.** A test loads each adapter wrapper's own family table (garak `PROBE_FRAMEWORKS`,
   pyrit `STRATEGY_FRAMEWORKS` + `DEFAULT_FRAMEWORKS`, promptfoo `PLUGIN_FAMILY` +
   `DEFAULT_FAMILY`) and the echo adapter's output. It asserts that every id they emit for a family
   is in the core table's entry for that family's rule id. An adapter that adds an id the core
   table lacks fails CI.

## Seed coverage

| Key | ATLAS | OWASP LLM 2025 | OWASP LLM 2026 | NIST AI RMF |
|---|---|---|---|---|
| `garak.promptinject` | AML.T0051 | LLM01 | LLM01 | MEASURE-2.7 |
| `garak.dan` | AML.T0054 | LLM01 | LLM01 | MEASURE-2.7 |
| `garak.leakreplay` | AML.T0057 | LLM02 | LLM02 | MEASURE-2.10 |
| `garak.xss` | — | LLM05 | LLM10 | MEASURE-2.7 |
| `pyrit` (default), `pyrit.tap`, `pyrit.pair` | AML.T0051 | LLM01 | LLM01 | MEASURE-2.7 |
| `pyrit.crescendo`, `pyrit.skeleton_key` | AML.T0054 | LLM01 | LLM01 | MEASURE-2.7 |
| `promptfoo.prompt-extraction` | AML.T0051 | LLM07 | LLM01 | MEASURE-2.7 |
| `promptfoo.harmful` | AML.T0048 | — | LLM07 | MEASURE-2.6 |
| `promptfoo.pii` | AML.T0057 | LLM02 | LLM02 | MEASURE-2.10 |
| `promptfoo` (default) | — | — | LLM07 | — |
| `echo.inject` | AML.T0051 | LLM01 | LLM01 | MEASURE-2.7 |
| `echo.leak` | AML.T0057 | LLM02 | LLM02 | MEASURE-2.10 |
| `mcp-scanner.tool-poisoning` | AML.T0053 | — | — | — (OWASP Agentic ASI04) |

The ATLAS and OWASP ids are the ones the adapters already emit, so the merge adds ids and changes
none. NIST AI RMF 1.0 subcategories: MEASURE 2.6 (safety risks), MEASURE 2.7 (security and
resilience), MEASURE 2.10 (privacy risk). The garak family has no default: an unknown garak probe
is `unmapped`, which is the point.

## Acceptance criteria

- [x] The table loads with a version and a source for every framework it uses; a malformed table
      fails the core tests.
- [x] Longest-prefix matching on `.`/`:` boundaries: family probes match their family, a tool key
      is the default, a non-boundary prefix does not match.
- [x] `merge_mappings` keeps the finding's ids, adds the table's, de-duplicates, and returns the
      `unmapped` marker only when both are empty.
- [x] An echo run stores findings carrying the table's NIST and OWASP 2025 ids, without moving
      their fingerprints.
- [x] `GET /report` includes `mapping_tables`, and the HTML report prints the versions.
- [x] The drift test fails if an adapter wrapper emits an id the core table lacks for that family.

## Test cases

Unit (`core/khandaq-core/tests/core.rs`): `the_builtin_table_names_a_version_and_source_per_framework`,
`longest_prefix_on_a_boundary`, `merge_keeps_adapter_ids_and_adds_the_table`,
`merge_marks_unmapped_only_when_both_are_empty`; the existing `map_frameworks_known_and_unmapped`.
Bindings (`core/khandaq-py/tests`): `merge_mappings` and `mapping_table` round-trip.
Integration (`api/tests/test_mappings.py`): echo run → stored mappings include `nist-ai-rmf` and
`owasp-llm-2025` and the fingerprint matches the pre-merge identity; report carries
`mapping_tables`; an unknown rule stores `unmapped`; the adapter drift guard.

## Out of scope

- A self-hoster's overlay table (`KHANDAQ_MAPPINGS_PATH`) for an internal taxonomy (follow-up).
- EU AI Act references (ADR-0012 lists them; they need an article-level crosswalk of their own).
- Removing the adapters' own dicts: they stay as the tool-side view, guarded against drift by the
  test above. Thinning them is a change to released adapter images, so it gets its own spec.
- Re-mapping findings stored before this spec (they are evidence of what was reported then).
