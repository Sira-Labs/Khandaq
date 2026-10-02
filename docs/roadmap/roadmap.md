# Roadmap

Khandaq is built in releases, each a coherent, demoable step. Design is spec-driven: a story gets a
spec in `docs/specs/` before any code, with the backlog and session notes in `TASKS.md`.

## Milestones

| Release | Theme | Exit criteria |
|---|---|---|
| **R0** | Design | Vision, architecture, domain model, scope/authz design, research synthesis, first ADRs, opening specs, roadmap, deployment plan, product page. *This repository state.* |
| **R1** | The spine | Engagements + scope lock + authz + audit; canonical findings model (fingerprint, dedup, severity, mapping); hash-chained evidence ledger; adapters for garak, PyRIT, promptfoo, Cisco mcp-scanner; web console (engagements, runs, findings inbox); a first management + technical report; a bundled intentionally-vulnerable local target; CapRover deploy to staging. A full engagement (scope → run suites → deduped findings → sealed evidence → report) works end to end against the bundled target. |
| **R2** | Coverage | Adapters for ART (adversarial ML & privacy), model/AI-BOM/dataset supply chain, Snyk agent-scan; guardrail-regression harness; **campaigns** (scheduled re-runs, diffs, drift alerts); wider framework export and Navigator layers. Continuous monitoring of a target with regression alerts works. |
| **R3** | Forensics & platform | IR/forensics (OTel GenAI / Langfuse trace import → incident timelines; findings → detections); full framework/Navigator exports; SSO/SCIM; API tokens hardening; multi-node adapter runners; production promotion flow. |

## Sequencing rationale

- **R1 proves the thesis before widening.** The differentiators are the spine (findings model, evidence,
  scope, report), not the number of tools. R1 wraps only the healthiest, most permissive, highest-demand
  tools (phases 03, 04, 07) and gets one engagement working end to end.
- **R2 widens coverage and adds memory.** More phases via more thin adapters, plus the campaign/diff
  loop that turns a snapshot into monitoring — the feature the market lacks.
- **R3 goes where nothing open-source is good:** forensics and incident reconstruction, plus the platform
  features (SSO/SCIM, multi-node) a team buyer needs.

## Dependencies & owner tasks

Software scope is on the sprint plan (`sprints.md`). Items that wait on people or third parties do not
compress with the forecast:

- Production CapRover server, Keycloak realm, evidence-encryption key / KMS story, backup location
  (ADR-0010) — owner.
- Confirm the public name/domain is free (GitHub org `Sira-Labs/Khandaq` is taken; check PyPI and a
  domain if one is wanted) — owner.
- Any pilot engagement is run only against systems with signed authorisation — owner.

## Non-goals (tracked so they are not scope-crept in)

Network-scale shadow-AI discovery; being an inline runtime guardrail; certifying compliance; any
offensive capability beyond orchestrating suites against authorised targets. See `docs/VISION.md`.
