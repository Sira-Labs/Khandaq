# Taxonomies and frameworks

Khandaq's value is partly that every finding gets a durable address in the standards a client, auditor
and regulator already use. This note records the frameworks we map to and the mapping approach
(ADR-0012). Snapshot: late Sep / early Oct 2026.

## MITRE ATLAS

Adversarial Threat Landscape for AI Systems: tactics, techniques, sub-techniques, mitigations and
case studies for attacks on AI. As of the Sep 2026 release it had grown substantially (on the order of
16 tactics and 120+ techniques, with many agentic additions, and some renames — e.g. the former "AI
Attack Staging" tactic was renamed). Machine-readable via `mitre-atlas/atlas-data` (YAML at
`dist/ATLAS-latest.yaml`), with an `atlas-to-stix` generator (STIX 2.1), Navigator layers, and a
reference REST API. The old `atlas-navigator-data` repo is deprecated.

**Use in Khandaq:** ATLAS is the backbone taxonomy. Findings carry ATLAS technique IDs; we export a
**Navigator layer** per engagement. No upstream tool emits ATLAS IDs natively, so the mapping is ours
to build and maintain (`core/khandaq-core/mappings/atlas/`).

## OWASP Top 10 for LLM Applications — 2025 and 2026

Two editions are in play, and we keep **both** on every finding (ADR-0012), because a client
questionnaire or a course may reference either.

The 2026 edition (released at the OWASP Global AppSec event in 2026) revises the list. Illustrative
2026 categories (verify against the published list before relying on IDs):

| ID | 2026 category (as recorded) |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Excessive Agency |
| LLM04 | Supply Chain |
| LLM05 | Data & Model Poisoning |
| LLM06 | Unbounded Consumption |
| LLM07 | Misinformation |
| LLM08 | Hidden Context Exposure (replaces the 2025 "System Prompt Leakage") |
| LLM09 | Vector & Embedding Weaknesses |
| LLM10 | Improper Output Handling |

The 2025 edition differs in ordering/wording for several items; the mapping tables hold both, with
`framework_version` recorded.

## OWASP Top 10 for Agentic Applications (ASI)

A newer list (ASI01–10) for agent-specific risks (e.g. tool misuse, memory poisoning, cascading agent
failures). Khandaq maps agent/MCP findings (phase 07) to ASI IDs in addition to the LLM list.

## NIST AI RMF

The AI Risk Management Framework's functions — **Govern, Map, Measure, Manage** — give programme-level
language. Findings are tied to the relevant function/subcategory (notably under *Measure*) so a report
speaks to a governance audience, not just an engineer.

## EU AI Act

Not a technical taxonomy but a set of obligations. For high-risk systems there are duties around risk
management, robustness and testing; the high-risk obligations' main application date moved to late 2027.
Khandaq references the relevant obligations so a report can show **where a finding touches a compliance
duty** — it does not certify compliance.

## Other reference data

- **AI Incident Database** and **AVID** — for IR/forensics context (phase 10).
- **CycloneDX 1.7 ML-BOM** and **SPDX 3.0 AI** — BOM output formats for the supply-chain phase.

## Mapping approach (ADR-0012)

- Mappings are **versioned data** in `core/khandaq-core/mappings/`, one directory per framework, each
  file carrying `framework_version` and a source citation.
- The map keys on {source tool rule id} and/or {finding nature}; a finding records **all** applicable
  IDs across frameworks and both OWASP years.
- Fixture tests assert that known findings map to expected IDs, so a mapping regression fails CI.
- Updating for a new ATLAS release or OWASP revision is a **data change with a test**, not a code change.
- Exports: framework-filtered reports + a MITRE ATLAS Navigator layer, generated from the tables.

## Maintenance note

ATLAS and OWASP move; a standing task (`TASKS.md`) keeps the mapping tables current and cites sources.
Because mappings are data, a self-hoster can extend them for an internal taxonomy without forking code.
