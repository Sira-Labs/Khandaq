# ADR-0012: Framework mappings are versioned data; OWASP LLM 2025 and 2026 kept in parallel

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

No upstream tool emits MITRE ATLAS IDs natively, and the OWASP LLM Top 10 exists in both a 2025 and a
2026 edition (with renumbering/renaming — e.g. the 2026 list revises several categories). A client's
questionnaire or a course may reference either year. Mapping a finding to the right framework IDs is
one of Khandaq's distinctive contributions and must be maintainable without code changes.

## Decision

- Ship the cross-walk as **versioned data** in the core (`core/khandaq-core/mappings/`): tables from
  {tool rule id / finding nature} → framework IDs for MITRE ATLAS, OWASP LLM **2025** and **2026**
  (kept in parallel, both emitted on a finding), OWASP Agentic (ASI), NIST AI RMF, and EU AI Act
  references. Each mapping file carries a `framework_version` and a source citation.
- A finding records **all** applicable framework IDs, so a report can be rendered against whichever the
  audience uses. Exports include a **MITRE ATLAS Navigator layer** generated from the mappings.
- Updating a mapping (new ATLAS release, OWASP revision) is a data change with a test, not a code
  change; mapping tables have fixture tests that assert known findings map to expected IDs.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Hard-code mappings in Rust/Python | Simple at first | Every framework update is a code change; brittle | Data is maintainable |
| Only the newest OWASP edition | Less to maintain | Breaks clients/courses on the older edition | Keep both in parallel |
| Rely on tools' own mappings (promptfoo presets) | Free | Inconsistent, incomplete, no ATLAS | Build the table ourselves |
| **Versioned mapping data, both OWASP years (chosen)** | Maintainable, auditable, dual-edition | Tables to curate | Accepted |

## Consequences

- A curation task exists to keep ATLAS and OWASP mappings current (tracked in `TASKS.md`); mapping
  files cite their sources and version.
- Because mappings are data, a self-hoster can extend them for an internal taxonomy without forking code.
- Reports and the Navigator export are driven entirely by these tables.
