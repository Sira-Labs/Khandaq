# Tool landscape (by phase)

A snapshot (late Sep / early Oct 2026) of the open-source tools Khandaq orchestrates or evaluates,
with licence, maintenance and acquisition notes. Figures age fast — re-check before pinning. This note
is about *which tools to wrap and how healthy they are*, not how to attack anything.

## Consolidation watch (affects adapter risk — ADR-0001)

The AI-security tooling market is consolidating; several projects changed hands or moved:

- promptfoo → **OpenAI** (Mar 2026); stays MIT.
- Invariant Labs → **Snyk** (2025); `mcp-scan` became `snyk/agent-scan`.
- Protect AI → **Palo Alto Networks** (2025); `llm-guard` archived (2026).
- Lakera → **Check Point**; SPLX → **Zscaler**; Prompt Security → **SentinelOne**;
  CalypsoAI → **F5**; Pangea → **CrowdStrike**; Promptfoo → **OpenAI**; TrojAI → **A10**.
- Repo moves: PyRIT is now `microsoft/PyRIT` (the `Azure/PyRIT` repo is archived); Giskard's v3 is a
  rewrite under `Giskard-AI/giskard-oss`.
- Still independent: HiddenLayer, Mindgard, Repello.

**Implication:** pin exact versions, keep adapters thin and cheap to replace, prefer permissive
licences and healthy maintenance, and watch for abandonment after an acquisition.

## Phase 03 — Scanning & fuzzing

| Tool | Maintainer | Licence | Notes |
|---|---|---|---|
| **garak** | NVIDIA | Apache-2.0 | Broad model-level probing; JSONL + HTML reports; no native OWASP/ATLAS mapping (we add it). Primary R1 adapter. |
| **promptfoo** | OpenAI | MIT | App-level test suites; multi-turn; presets for OWASP/ATLAS/NIST/EU AI Act; no native SARIF. Primary R1 adapter. |
| **DeepTeam** | Confident AI | Apache-2.0 | 50+ vulnerability types; maps to OWASP/ATLAS/NIST. Good Python-native alternative. |
| **Giskard (v3)** | Giskard-AI | Apache-2.0 | Scanning + evaluation; v3 rewrite. |

Best mix: garak for breadth, promptfoo for app-level + compliance presets, DeepTeam as a Python
alternative.

## Phase 04 — Prompt injection

| Tool | Maintainer | Licence | Notes |
|---|---|---|---|
| **PyRIT** | Microsoft | MIT | Orchestrators, converters, scorers; `pyrit_scan` CLI. The depth tool for this phase; primary R1 adapter. |
| **promptfoo** | OpenAI | MIT | CI-friendly regression of injection test suites. |
| **AgentDojo** (via **Inspect**, UK AISI) | research | permissive | A benchmark harness for agent prompt-injection; run through Inspect. |

Best mix: PyRIT for depth, promptfoo for CI regression, AgentDojo-via-Inspect as a benchmark.

## Phase 07 — Agentic, MCP & A2A

| Tool | Maintainer | Licence | Notes |
|---|---|---|---|
| **Cisco mcp-scanner** | Cisco | permissive | YARA rules + LLM judge + dataflow; CLI, SDK, REST. Primary R1 MCP adapter. |
| **Snyk agent-scan** (ex Invariant `mcp-scan`) | Snyk | — | Needs `SNYK_TOKEN`; sends metadata to Snyk (note for air-gapped/self-host). |
| **Cisco a2a-scanner** | Cisco | permissive | Agent-to-agent; smaller, newer (R2+). |

Benchmarks: ASB, A2ASecBench. A2A coverage is immature across the board.

## Phase 05 — Adversarial ML & privacy

| Tool | Maintainer | Licence | Notes |
|---|---|---|---|
| **ART** (Adversarial Robustness Toolbox) | LF AI | MIT | The main engine for evasion/extraction/poisoning across frameworks. R2 adapter. |
| **TextAttack** | QData | MIT | NLP adversarial examples. |
| **ML Privacy Meter** | NUS/academia | permissive | Membership inference (RMIA); state of the art. |

Classical-ML and LLM tooling are separate; there is no maintained cross-framework runner (a gap).

## Phase 06 — Data & training pipeline

| Tool | Licence | Notes |
|---|---|---|
| **cleanlab** | permissive | Data hygiene / label-error detection. |
| **ART (defences)** | MIT | Poisoning/backdoor defences. |
| provenance: **Croissant**, Data Provenance Initiative, **OMS** | — | Dataset provenance / model signing. |
| BackdoorBench | **CC BY-NC** | Non-commercial — **do not bundle** in a commercial suite; evaluate only. |

Most backdoor tooling is image-only and research-grade; the realistic R2 build is a **dataset-gate**
(hash manifest + cleanlab/ART detectors + Croissant checks) emitting CycloneDX.

## Phase 08 — Infrastructure & supply chain

| Tool | Licence | Notes |
|---|---|---|
| **ModelAudit** (promptfoo) | permissive | 45+ scanners; SARIF + CycloneDX output. Good fit for the schema. |
| **ModelScan** (Protect AI) | permissive | Community-maintained; no ONNX/GGUF. |
| **Fickling** | LGPL | Pickle analysis; licence note. |
| picklescan | permissive | Had bypasses in 2025 → run **several scanners together** (consensus). |
| signing: **sigstore model-signing (OMS)** | — | Verify-signature gate. |
| BOM: **CycloneDX 1.7 ML-BOM**, SPDX 3.0 AI | — | Output formats. |
| **AI-Infra-Guard** (Tencent) | permissive | Infra scanning, MCP scanning, large CVE set. |

Build (R2): a **scanner-consensus wrapper** (merge several scanners' SARIF) + a **verify→scan→admit**
gate, since single scanners have had critical bypasses.

## Phase 09 — Guardrails & hardening

| Tool | Licence | Notes |
|---|---|---|
| **NeMo Guardrails** | Apache-2.0 | Guardrail framework to test against. |
| **Guardrails AI** | permissive | Validators. |
| **PurpleLlama / LlamaFirewall / Llama Guard / Prompt Guard** | Meta | Guard models/firewall. |
| LLM Guard | archived | **Do not build on it.** |
| open-weight guards: gpt-oss-safeguard, Qwen3Guard, Granite Guardian, Shieldstral | — | Guard models. |

Gap: nothing replays an attack corpus against a guardrail config and tracks **block rate + false-positive
drift**. That is the R2 guardrail-regression harness.

## Phase 10 — IR & forensics

| Area | Tools | Notes |
|---|---|---|
| Telemetry | **OTel GenAI** semantic conventions (pre-stable), **Langfuse** (MIT core; acquired by ClickHouse), Arize Phoenix (ELv2), OpenLLMetry, OpenLIT, Opik | Trace sources to import. |
| Registries | AI Incident Database, AVID, OWASP Agentic (ASI) Top 10, MCP CVEs | Reference data. |
| Playbooks | CoSAI AI IR Framework v1.0, OWASP GenAI IR Guide, NIST SP 800-61r3 | Process. |

Nothing is operations-ready; importing OTel/Langfuse traces to build **incident timelines** is the R3
differentiator.

## Phase 02 — Recon & inventory

Tools: Cisco aibom / agent-bom, Snyk agent-scan, OWASP AIBOM Generator, safedep vet. Commercial:
Wiz AI-SPM, Defender CSPM. **Gap:** nothing open-source discovers AI use from network/egress traffic
(out of scope for now; see VISION "not").

## What R1 wraps

garak, PyRIT, promptfoo (phases 03–04) and Cisco mcp-scanner (phase 07) — the healthiest, most
permissive, highest-demand tools — proving the spine end to end before widening coverage in R2.
