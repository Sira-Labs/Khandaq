# Gaps and what to build

What no open-source tool does today, and which gaps Khandaq closes. This is the product thesis distilled
from the landscape research. Snapshot: late Sep / early Oct 2026.

## The gaps (consistent across every phase)

1. **No common findings format.** Each tool has its own output; few emit SARIF; none emits ATLAS IDs.
   Only tiny, unmaintained projects attempt cross-tool aggregation.
2. **No cross-tool deduplication or shared severity.** The same issue found by three tools is three
   results, with three severities.
3. **No chain of evidence.** Nothing binds prompts/responses/artefacts to an engagement with a
   tamper-evident record.
4. **No enforced scope.** Tools trust whatever target you give them; there is no shared authorisation
   boundary.
5. **No regression tracking.** Engagements are snapshots; nothing watches for a defence that regresses.
6. **Fragmented framework reporting.** Nothing combines OWASP LLM + Agentic + ATLAS + NIST + EU AI Act
   into one report.
7. **No guardrail-drift measurement.** Nothing replays an attack corpus against a guardrail config and
   tracks block rate and false-positive drift.
8. **IR/forensics is wide open.** No tool links findings → runtime detections → incident timelines.

## What Khandaq builds (and the release that lands it)

| Gap | Khandaq's answer | Where |
|---|---|---|
| 1, 2 | Canonical SARIF-superset finding + stable fingerprint + cross-tool dedup + per-adapter severity map | Core (ADR-0003/0004), R1 |
| 6 | Versioned framework mapping tables (ATLAS, OWASP LLM 2025/2026, ASI, NIST, EU AI Act) + Navigator export | Core (ADR-0012), R1→R2 |
| 3 | Append-only, hash-chained, optionally-signed evidence ledger; reports pin the root | Core (ADR-0007), R1 |
| 4 | Engagement + server-side scope lock + per-run egress containment + audit log | API (ADR-0009, scope doc), R1 |
| 5 | Campaigns: scheduled re-runs + diff (new/resolved/regressed) + alerts | Core diff + worker, R2 |
| 7 | Guardrail-regression harness: replay corpus vs config, track block/FP drift | R2 |
| 8 | Import OTel GenAI / Langfuse traces → incident timelines; findings → detections | R3 |

## Feasibility (from the research)

- **High (do first):** the findings schema with adapters, fingerprint dedup, regression diffs, the
  framework mapping table, Docker-isolated runners with scope manifests, scheduling, and local (offline)
  LLM judges where a tool needs one. This is R1–R2 and is squarely buildable by a small team.
- **Medium:** an ephemeral sandbox harness for a customer's own agents + their MCP servers; the
  guardrail-regression harness; the supply-chain scanner-consensus gate.
- **Low / later:** network-scale shadow-AI discovery, proprietary detection models, large original
  attack corpora. Out of scope for now.

## Deliberate non-goals (keep the thesis tight)

- Do **not** reimplement attacks (ADR-0001) — orchestrate.
- Do **not** become an inline runtime guardrail — test and monitor them instead.
- Do **not** build network discovery at scale now — it is the weakest-ROI gap for a small team.
- Do **not** depend on a cloud service for core function — self-host, air-gap-friendly; note tools that
  phone home (e.g. agent-scan's metadata to Snyk) and make that explicit in the adapter.

## Why this wins

The attack tools are commodities and are consolidating under big vendors. The **disciplined spine** —
one findings model, provable evidence, enforced scope, framework-mapped reports, and continuous
regression — is what a professional actually needs and what nobody ships self-hosted. Khandaq owns the
spine and rents the attacks.
