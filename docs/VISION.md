# Khandaq — Vision

*Khandaq* (الخندق) is the trench dug around Medina in the fifth year of the Hijra to meet a
confederate siege. The idea came from **Salmān al-Fārisī** — carried in from outside the
Arabian tradition of warfare — and during the same siege the Prophet ﷺ sent **Ḥudhayfa ibn
al-Yamān** alone into the enemy camp at night to learn their condition. The defence of the
city turned on two things: **preparing the ground before the attack came**, and **seeing the
attacker clearly**. That is what this project builds for AI systems.

**Orchestrate the attack you are allowed to run. Keep the record straight. Watch for the day it breaks.**

## The problem

An AI security professional in 2026 has a shelf of excellent open-source tools — garak for
model-level probing, PyRIT for multi-turn attacks, promptfoo for app-level test suites, ART
for adversarial ML, model scanners for unsafe serialisation, MCP scanners for agent tooling.
Each is good at one thing. None of them knows about the others.

The result is that the hard, unglamorous, *essential* parts of an engagement have no home:

- **The findings don't add up.** garak writes JSONL, promptfoo writes its own JSON, a model
  scanner writes SARIF if you are lucky. Nobody deduplicates a prompt-injection that three
  tools found, agrees on its severity, or maps it to a MITRE ATLAS technique and an OWASP LLM
  ID — so the client report is assembled by hand, differently every time.
- **The evidence doesn't hold.** The prompts, responses and artefacts that *prove* a finding
  scatter across temp directories and get lost. Nothing binds them to an engagement, timestamps
  them, or makes the record tamper-evident — which is exactly what a client, an auditor, or a
  court needs.
- **The scope isn't enforced.** Offensive tools trust whatever target you type. Running them
  against the wrong host is not a bug, it is a legal event. There is no shared, enforced
  authorisation boundary.
- **The result has no memory.** An engagement is a snapshot taken on one afternoon. The moment a
  model version, a system prompt, or a guardrail config changes, the snapshot is stale — and
  nothing is watching to tell you that a defence which passed last month regressed today.

The tools are not the gap. The **campaign around them** is the gap.

## Why now

- The tooling finally exists and is maintained: garak, PyRIT, promptfoo, DeepTeam, ART, Cisco's
  MCP scanner, Snyk's agent-scan, ModelAudit. The attack surface is understood well enough to
  orchestrate.
- The **taxonomies are stable enough to map against**: MITRE ATLAS, the OWASP LLM Top 10 (2025
  and the 2026 revision), the OWASP Agentic (ASI) Top 10, NIST AI RMF. A finding can be given a
  durable address.
- **Obligations are arriving.** The EU AI Act's high-risk duties, NIST's framework, and client
  security questionnaires all now ask for evidence of AI red teaming. The demand for a repeatable,
  documented, defensible process is real.
- **The market is consolidating** — many standalone AI-security vendors have been acquired. A
  self-hosted, vendor-neutral orchestrator that you own is more valuable, not less, when the
  commercial layer is churning.

## Who this is for

| Persona | Needs | Typical action |
|---|---|---|
| **Offensive AI security consultant** | Run a full, defensible engagement across the ten phases and produce a client report that maps to the frameworks. | Opens an engagement, runs suites, reviews findings, exports the report with its evidence bundle. |
| **In-house AI red teamer / AppSec** | Continuously test the org's own LLM apps and agents; catch regressions before release. | Schedules campaigns against staging, triages drift alerts, files tickets. |
| **ML / platform security engineer** | Verify models and the serving supply chain before deployment. | Runs model-scan and AI-BOM suites in CI as an admission gate. |
| **AI governance / compliance lead** | Show auditors that red teaming happened, what it found, and that the record is intact. | Reads framework-mapped reports; relies on the signed evidence ledger. |
| **Platform admin** | Who can run what, against which targets? What did the system do? | Manages users, roles, engagements, scope policy and the audit log. |

## What Khandaq is

A self-hosted command post for authorised AI red-team engagements:

- **Engagement-first.** Nothing runs outside an engagement with declared, authorised targets and
  rules of engagement. A server-side **scope lock** refuses anything out of bounds; an append-only
  **audit log** records every privileged action.
- **An orchestrator, not an attacker.** Khandaq launches the published tools — each in an isolated,
  version-pinned container through a thin adapter — and never implements an attack itself.
- **One findings model.** Every tool's output is normalised into a canonical schema (a SARIF
  superset), fingerprinted, **deduplicated across tools**, given a shared severity, and mapped to
  ATLAS, OWASP LLM (2025 + 2026), OWASP Agentic and NIST AI RMF.
- **A chain of evidence.** Prompts, responses and artefacts are stored append-only and sealed into
  a **hash-chained, optionally Sigstore-signed** bundle, so a report is reproducible and
  tamper-evident.
- **Reports that map.** One engagement becomes a management summary and a technical report, each
  cross-walked to the frameworks a client, auditor and regulator use.
- **Continuous by default.** A suite becomes a **campaign**: scheduled re-runs, a diff against the
  baseline, and an alert the day a defence regresses or a new finding appears.
- **Local by default.** One `docker compose up`, or CapRover. Your engagement data never leaves your
  infrastructure. No phone-home.

## Product principles

1. **Authorised use is enforced, not assumed.** The scope lock, audit log and evidence integrity are
   the product. They are tested, and a change that weakens them is a security defect.
2. **Orchestrate, don't reimplement.** The upstream tools stay upstream. Khandaq's value is the
   spine between them, not a new exploit. No offensive payloads live in this repository.
3. **Every finding has an address and evidence.** A result is only useful if it carries its proof
   and maps to a framework ID someone is accountable for.
4. **Thin, pinned adapters.** A tool is wrapped at an exact version with a contract test, so an
   upstream change fails CI instead of silently corrupting findings.
5. **Reproducible and tamper-evident.** Re-running an engagement should produce comparable results;
   the evidence record should be verifiable after the fact.
6. **Self-hosted and sovereign.** No hosted control plane, no required third-party service for core
   function; air-gapped-friendly.

## What Khandaq deliberately is not

- **Not a new attack framework.** It ships no novel exploits, payloads or evasion techniques. It
  orchestrates published, maintained tools.
- **Not a tool for unauthorised testing.** Out-of-scope runs are refused, not warned about. It is
  built to keep an engagement inside the boundary you are allowed to test.
- **Not a SaaS.** There is no hosted control plane and there will not be one. Your evidence stays on
  your infrastructure.
- **Not a replacement for the upstream tools.** garak, PyRIT and the rest are not vendored or
  relicensed; Khandaq commands them and keeps their findings together.
- **Not a guardrail or a runtime defence.** Khandaq tests and monitors; it is not an inline filter
  in front of a production model. (It can *validate* a guardrail's configuration over time; it does
  not *be* one.)
- **Not a generic SIEM or a compliance-certification product.** It produces evidence and
  framework-mapped reports; it does not certify anyone.

## Scope of the first releases

- **R0 (design):** vision, architecture, domain model, engagement/scope/authz design, research
  synthesis, first ADRs, opening specs, roadmap, deployment plan. *This repository state.*
- **R1 (the spine):** engagements, the scope lock, authz and the audit log; the canonical findings
  model with fingerprinting, dedup and framework mapping; the hash-chained evidence ledger; the
  first adapters (garak, PyRIT, promptfoo) for the prompt-injection and scanning phases; the web
  console (engagements, runs, findings inbox); a first report; a bundled intentionally-vulnerable
  local target for demos and tests.
- **R2 (coverage):** adapters across the remaining phases — adversarial ML and privacy (ART),
  data/pipeline and supply chain (model scanners, AI-BOM, dataset gates), agentic/MCP (Cisco
  mcp-scanner, Snyk agent-scan); the guardrail regression harness; campaigns and drift alerts.
- **R3 (forensics & platform):** IR and forensics (OTel GenAI / Langfuse trace import, timelines),
  the Navigator-layer and full framework exports, SSO/SCIM, API tokens, multi-node adapter runners.

Out of scope for now: network-scale shadow-AI discovery, proprietary detection models, and any
offensive capability beyond orchestrating suites against systems you are authorised to test.

## The family

Khandaq joins the Sīra Labs projects, each named for a moment in the Sīra and each self-hostable:
**Thawr** (the cave of the Hijra — a private network, protection), **Tabayyun** (verifying a report
before acting on it — time-series data quality), and now **Khandaq** (preparing the defence by
thinking like the attacker — AI red teaming).
