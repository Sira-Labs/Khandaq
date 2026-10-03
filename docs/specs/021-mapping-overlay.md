# Spec 021 — Deployment overlay for the framework mapping table

Sprint 5, story S5-5. Depends on: 020. Packages: `core/` (mappings, CLI, wheel), `api/` (settings,
runs, reports), `deploy/`, `docs/`.

## Goal

ADR-0012 promises that "a self-hoster can extend [the mapping tables] for an internal taxonomy
without forking code". Spec 020 made the built-in table the source of truth but left no way to
extend it. When this spec is done, a deployment can point `KHANDAQ_MAPPINGS_PATH` at a JSON file in
the same `khandaq.mappings/1` schema. The file adds rules, replaces built-in rules, and adds
frameworks such as an internal control catalogue. The API and the worker apply the combined table at
ingest. Every report says whether an overlay was in effect and which one, by its sha256. A malformed
overlay stops the app from starting, in every environment.

## User story

As a security lead self-hosting Khandaq, I map our internal control ids (`acme-ctl`) onto the rules
our tools report, and I correct one built-in entry for our context. Every report then shows both
our ids and the fingerprint of the overlay that produced them.

## Interface

- **Config.** `KHANDAQ_MAPPINGS_PATH`: the path to an overlay file (default empty, meaning no overlay). Set it on
  the API and the worker; both ingest findings.
- **Overlay file.** The `khandaq.mappings/1` schema from spec 020. `versions` and `sources` name
  only the frameworks the overlay introduces; built-in frameworks may be repeated with the **same**
  version and source. Size limit 1 MiB.
- **Core.** `Mappings::with_overlay(&self, text) -> Result<Mappings, MappingsError>`.
- **Wheel.** `merge_mappings(finding_json, overlay=None)` and `mapping_table(overlay=None)`. The
  optional argument is the overlay text.
- **CLI.** `khandaq-core normalize FILE --mappings OVERLAY`.
- **Finding.** Each finding records the table that mapped it in `x-khandaq.mapping_table`:
  `{"versions": {...}, "overlay": null | {"name", "sha256"}}`.
- **Report.** `mapping_tables` describes the table in effect now (`versions`, `sources`, `overlay`).
  It also lists the tables recorded on the report's findings, as `recorded: [{versions, overlay,
  findings: n}]`, with `unrecorded: n` for findings stored before this spec. The HTML report prints
  both.

## Behaviour

1. **Combine.** The combined rules are the built-in rules, with each overlay key **replacing** the
   built-in entry of the same key; other keys are added. Prefix matching (spec 020) runs over the
   combined keys. An overlay entry `garak` therefore becomes garak's default.
2. **Frameworks.**
   - An overlay may introduce a framework by naming its version and source.
   - It may not change a built-in framework's version or source. Two tables claiming different
     ATLAS releases would make every report ambiguous, so this is an error, not an override.
   - Every framework used by the combined rules must have a version and a source, as in spec 020.
3. **Validation.**
   - At startup (API and worker), in every environment, a set path that is unreadable, larger than
     1 MiB, not valid JSON, not the schema, or failing rule 2 stops the app with the reason.
   - A broken overlay must not silently fall back to the built-in table: that would quietly drop a
     deployment's own ids from every report.
4. **Ingest.** `merge_mappings` uses the combined table. The overlay is read once per process and
   cached; changing it takes a restart, the same as any other setting.
5. **Provenance.** At ingest, every finding records the framework versions and the overlay, by
   name and the sha256 of its exact bytes, that produced its ids. A report lists each distinct
   recorded table with its finding count, and separately the table in effect now. A restart under
   another overlay, or none, therefore never changes what a report says produced an older
   engagement's ids. Findings stored before this spec are counted as `unrecorded`, never
   attributed to the current table (PR #38 review).
6. **No identity change.** Mappings are not identity (ADR-0013). Adding or editing an overlay moves
   no fingerprint and re-maps no stored finding.

## Acceptance criteria

- [x] An overlay adds a rule, replaces a built-in rule and introduces a framework; the combined
      table matches by longest prefix over both.
- [x] An overlay that changes a built-in framework's version or source, uses a framework with no
      version, or is not the schema, is refused with a reason.
- [x] A bad `KHANDAQ_MAPPINGS_PATH` (missing, too large, invalid) stops the app at startup in dev
      and prod.
- [x] An echo run with an overlay stores the overlay's ids and records it on each finding; the
      report names it under `recorded` even after the overlay is removed; findings without a
      record are counted as `unrecorded`.
- [x] `khandaq-core normalize --mappings` applies the overlay.

## Test cases

Unit (`core/khandaq-core/tests/core.rs`): `an_overlay_adds_replaces_and_introduces`,
`an_overlay_cannot_change_a_builtin_framework`.
CLI (`core/khandaq-cli/tests/normalize.rs`): `normalize_applies_an_overlay`.
Bindings: `merge_mappings` and `mapping_table` with an overlay.
Integration (`api/tests/test_mapping_overlay.py`): echo run with an overlay → overlay ids stored,
recorded per finding, and still named by the report after the overlay is removed; legacy findings
counted as unrecorded; `validate_mappings` refuses missing, oversized and invalid files.

## Out of scope

- Per-engagement overlays. The table is deployment configuration, like the alert webhook.
- Editing the overlay from the console.
- EU AI Act references in the built-in table. They need an article-level crosswalk of their own.
