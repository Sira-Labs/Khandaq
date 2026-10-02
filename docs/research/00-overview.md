# Research overview

These notes synthesise the landscape research behind Khandaq: the open-source tools worth
orchestrating, the taxonomies to map against, the gaps nothing fills today, and the orchestration
platforms that came before. They are a **durable record of why the product is shaped the way it is**,
not operating instructions. They contain no attack payloads; they are about tools, licences,
maintenance health and standards.

Dates and figures were gathered in late September / early October 2026 and will age; treat star
counts, versions and acquisition notes as a snapshot and re-check before relying on them.

## The ten phases

Khandaq is organised around the offensive-AI lifecycle an AI security professional works through —
the structure the **EC-Council C|OASP** (Certified Offensive AI Security Professional) curriculum
follows. We use the ten phases only as an **organising spine for coverage and reporting**; Khandaq is
not affiliated with EC-Council and teaches no attacks.

| # | Phase | What the professional does | Where the OSS is |
|---|---|---|---|
| 01 | Methodology & taxonomy | Plan the engagement against ATLAS / OWASP | Mature (standards) |
| 02 | Recon & AI attack surface | Inventory models, agents, tools, data | Emerging |
| 03 | Scanning & fuzzing | Broad automated probing of a model/app | Strong |
| 04 | Prompt injection | Targeted adversarial prompting, multi-turn | Strong |
| 05 | Adversarial ML & privacy | Evasion, extraction, membership inference | Mature engine (ART), fragmented |
| 06 | Data & training pipeline | Poisoning/backdoor detection, provenance | Mostly research / image-only |
| 07 | Agentic, MCP & A2A | Test agents, MCP servers, agent-to-agent | Fast-moving, immature |
| 08 | Infrastructure & supply chain | Model scanning, signing, AI-BOM | Strong & consolidating |
| 09 | Guardrails & hardening | Validate defences, regression-test them | Guardrails exist; validation weak |
| 10 | IR & forensics | Detect, investigate, reconstruct incidents | Nascent; biggest gap |

The detail is in the companion notes:

- `01-tool-landscape.md` — the tools per phase, with licence, maintenance and acquisition status.
- `02-taxonomies-and-frameworks.md` — ATLAS, OWASP LLM (2025 & 2026), OWASP Agentic, NIST AI RMF,
  EU AI Act, and how we map to them.
- `03-gaps-and-what-to-build.md` — what no tool does, and which gaps Khandaq closes.
- `04-orchestration-platforms.md` — prior orchestration attempts and the commercial landscape.

## Headline conclusions (why Khandaq exists)

1. The **tools are good and maintained**; the **campaign layer is missing**. This is an orchestration
   and data-model problem, not an attack-research problem.
2. **No tool emits ATLAS IDs natively** and few emit SARIF. A canonical findings model with a
   maintained mapping table is the cheapest high-value original work (ADR-0003, ADR-0012).
3. **Nothing links findings → evidence → regression → report** across tools with a tamper-evident
   record. The scope lock, evidence ledger and campaign diff are the differentiators (ADR-0007, ADR-0009).
4. **The market is consolidating** (many acquisitions). A self-hosted, vendor-neutral orchestrator you
   own is more valuable when the commercial layer churns — and a reason to keep adapters thin and
   version-pinned (ADR-0001).
5. **Forensics (phase 10) is wide open.** Importing OTel GenAI / Langfuse traces to build incident
   timelines is the strongest way to stand out later (R3).
