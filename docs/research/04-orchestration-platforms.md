# Orchestration platforms (prior art) and the commercial landscape

What already tries to orchestrate AI red-team tooling, and why none of it is the product Khandaq aims
to be. Snapshot: late Sep / early Oct 2026.

## Open-source orchestration attempts

| Project | What it is | Why it is not enough |
|---|---|---|
| **EART** (Enterprise AI Redteam) | MIT; a dashboard over promptfoo, garak, PyRIT, DeepTeam | LLM-prompt focus only; very small/early (single-digit stars). A useful **design reference**, not a base to build on. |
| **BlackIce** (Databricks, Jan 2026) | A Docker image bundling ~14 tools ("Kali for AI") | Runtime image only — no orchestration, no findings model, no reporting, no scope/evidence. The opposite of our thin-adapter approach (ADR-0009). |
| **Dreadnode** | SDK + `agent-lens` | Only the SDK is open; not a self-hosted command post. |
| **AISRF / trustmcp** and similar | Tiny aggregation attempts | Unmaintained / 1–2 stars; prove the need, not the solution. |

**Takeaway:** the closest open-source thing (EART) is a thin dashboard; the most-tooled thing
(BlackIce) is an un-orchestrated image. The gap between them — a disciplined, self-hosted command post
with a real findings model, enforced scope, evidence and monitoring — is exactly Khandaq.

## Commercial landscape (and why self-hosted wins)

The commercial AI-security space is strong but **consolidating fast**:

- Acquisitions: Protect AI → Palo Alto; Lakera → Check Point; SPLX → Zscaler; Prompt Security →
  SentinelOne; CalypsoAI → F5; Pangea → CrowdStrike; Promptfoo → OpenAI; TrojAI → A10; Permiso → Okta.
- Still independent: HiddenLayer, Mindgard, Repello.
- Mindgard and peers are **commercial and not self-hostable** — unsuitable for air-gapped, sovereign,
  or "evidence must never leave our infrastructure" engagements.

**Implication for Khandaq:**

1. A **self-hosted, vendor-neutral** orchestrator you own is *more* valuable while the commercial layer
   churns and bundles into platforms.
2. Consolidation makes upstream OSS tools less predictable (abandonment, licence shifts). This is the
   direct justification for **thin, version-pinned adapters with contract tests** (ADR-0001) — a tool
   that dies is cheap to replace.
3. Our differentiators are precisely what commercial platforms keep proprietary and what no OSS tool
   offers together: the findings model + evidence ledger + scope discipline + framework-mapped reports
   + regression monitoring.

## Positioning in one line

Khandaq is the open, self-hosted **command post** that commands the open-source attack tools and keeps
a professional, provable record — sitting in the gap between a thin dashboard (EART) and an
un-orchestrated toolbox (BlackIce), and remaining yours when the commercial tools get acquired.
