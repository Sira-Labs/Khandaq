# Spec 011 — First engagement report

Sprint 4, story S4-5. Depends on: 002, 003, 004, 005. Packages: `api/` (reports).

## Goal

An engagement can be turned into a report: a management summary (counts by severity and framework, the
evidence-ledger status) and a technical report (every canonical finding with its mappings and evidence
refs), exported as JSON and HTML, plus a MITRE ATLAS Navigator layer. The report **pins the evidence
ledger root** so it is bound to the exact evidence it relies on (ADR-0007).

## Interface

- `GET /api/engagements/{id}/report` → JSON: `{engagement, generated_at, evidence: {root, verify},
  summary: {total, by_severity, by_framework}, findings: [...]}` (any member).
- `GET /api/engagements/{id}/report.html` → a self-contained HTML rendering (any member).
- `GET /api/engagements/{id}/report/navigator` → a MITRE ATLAS Navigator layer (from the core).

## Behaviour

1. The report covers the engagement's **canonical** findings. The summary counts by severity and by
   framework id (across all mappings). The evidence block carries the ledger root and verify result.
2. The Navigator layer is produced by the Rust core from the findings' ATLAS mappings.
3. All finding text is untrusted and escaped in the HTML rendering.

## Acceptance criteria

- [x] `report` JSON has correct severity/framework counts (1 high, 1 low; LLM01 + LLM02), the ledger
      root, and verify ok.
- [x] `report.html` returns `text/html` 200 and escapes finding text.
- [x] `report/navigator` returns an ATLAS layer listing the findings' techniques (AML.T0051).

## Test cases

Integration (`api/tests/test_report.py`): run echo → report counts (1 high, 1 low), frameworks include
LLM01/LLM02, ledger root present + verify ok; HTML 200 + escaping; navigator lists ATLAS techniques.

## Out of scope

PDF export; report templating/branding; scheduled report delivery (campaigns, R2).
