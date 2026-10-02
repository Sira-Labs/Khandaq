# Product vision (canonical)

> Narrative version: `docs/VISION.md`. This file is the structured reference that specs cite for
> personas, principles and release scope.

Khandaq is a self-hostable platform that runs **authorised** AI red-team engagements end to end:
it orchestrates the maintained open-source tools, unifies their findings into one model mapped to
the standard taxonomies, keeps a tamper-evident chain of evidence, reports against the frameworks,
and turns an engagement into a continuously-monitored campaign.

First target users: **offensive AI security consultants** running client engagements, and
**in-house AI red teams** continuously testing their own LLM apps and agents. First phases
implemented: **prompt injection** and **scanning/fuzzing** (modules 03–04), because that is where
the open-source tooling is strongest and the demand is highest.

## Product principles

1. **Authorised use is enforced, not assumed.** Scope lock, audit log and evidence integrity are
   tested invariants; weakening them is a security defect.
2. **Orchestrate, don't reimplement.** Upstream tools stay upstream; no offensive payloads in-repo.
3. **Every finding has an address and evidence.** Canonical schema, stable fingerprint, framework
   mapping, evidence refs.
4. **Thin, pinned adapters with contract tests.** Upstream drift fails CI, it does not corrupt data.
5. **Reproducible and tamper-evident.** Re-runs are comparable; the evidence record is verifiable.
6. **Self-hosted and sovereign.** No hosted control plane; air-gapped-friendly; no phone-home.

## Personas

| Persona | Needs | Typical action |
|---|---|---|
| Offensive AI security consultant | A full, defensible engagement across ten phases; a client report mapped to the frameworks. | Opens an engagement, runs suites, triages findings, exports report + evidence bundle. |
| In-house AI red teamer / AppSec | Continuous testing of the org's LLM apps/agents; regression detection. | Schedules campaigns against staging, triages drift alerts, files tickets. |
| ML / platform security engineer | Verify models and serving supply chain before deploy. | Runs model-scan / AI-BOM suites in CI as an admission gate. |
| AI governance / compliance lead | Evidence that red teaming happened and the record is intact. | Reads framework-mapped reports; relies on the signed ledger. |
| Platform admin | Control over who runs what against which targets. | Manages users, roles, engagements, scope policy, audit log. |

## The ten phases (coverage map)

Khandaq is organised around the offensive-AI lifecycle (the structure the EC-Council C|OASP
curriculum follows). For each phase it orchestrates upstream tools; it does not implement the
attacks itself.

| # | Phase | Primary orchestrated tools | Release |
|---|---|---|---|
| 01 | Methodology & taxonomy | MITRE ATLAS, OWASP LLM & Agentic Top 10 (as the mapping backbone) | R1 |
| 02 | Recon & AI attack surface | AI-BOM generators, inventory/discovery adapters | R2 |
| 03 | Scanning & fuzzing | garak, promptfoo, DeepTeam, Giskard | R1 |
| 04 | Prompt injection | PyRIT, promptfoo, garak; AgentDojo via Inspect | R1 |
| 05 | Adversarial ML & privacy | ART, TextAttack, ML Privacy Meter | R2 |
| 06 | Data & training pipeline | ART defences, cleanlab, dataset/provenance gates | R2 |
| 07 | Agentic, MCP & A2A | Cisco mcp-scanner, Snyk agent-scan | R1 (mcp), R2 (a2a) |
| 08 | Infrastructure & supply chain | ModelAudit, ModelScan, signing (OMS), CycloneDX | R2 |
| 09 | Guardrails & hardening | Guardrail regression harness (NeMo, LlamaFirewall) | R2 |
| 10 | IR & forensics | OTel GenAI & Langfuse trace import, timelines | R3 |

## Release scope

- **R0 — design.** This repository state: vision, architecture, domain model, scope/authz design,
  research synthesis, first ADRs, opening specs, roadmap, deployment plan.
- **R1 — the spine.** Engagements, scope lock, authz, audit log; canonical findings model with
  fingerprint, dedup and framework mapping; hash-chained evidence ledger; adapters for garak,
  PyRIT, promptfoo and Cisco mcp-scanner; web console (engagements, runs, findings inbox); first
  report; bundled intentionally-vulnerable local target.
- **R2 — coverage.** Adapters for ART, model/AI-BOM/dataset supply chain, agent-scan; guardrail
  regression harness; campaigns and drift alerts; wider framework export.
- **R3 — forensics & platform.** IR/forensics trace import and timelines; Navigator-layer and full
  framework exports; SSO/SCIM; API tokens; multi-node adapter runners.

## Out of scope (now)

Network-scale shadow-AI discovery; proprietary detection models; being an inline runtime guardrail;
certifying compliance; and any offensive capability beyond running suites against authorised targets.
