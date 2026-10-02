# ADR-0001: Orchestrate upstream tools via thin, pinned adapters — never reimplement attacks

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

The open-source AI red-team ecosystem has strong, maintained, single-purpose tools (garak, PyRIT,
promptfoo, DeepTeam, ART, model/MCP scanners). The gap in the market is not another attack tool; it
is the campaign layer around them: a shared findings model, evidence, scope control, reporting and
monitoring. We must decide whether Khandaq *implements* attack techniques or *orchestrates* existing
ones.

Two forces push hard toward orchestration. First, **safety and legitimacy**: a repository full of
novel exploit code is a liability, easy to misuse, and hard to defend as a professional product.
Second, **maintenance reality**: the attack space moves weekly; keeping our own exploits current
would consume the whole project, while the upstream communities already do that work.

## Decision

Khandaq **orchestrates** published, maintained tools and **never implements a novel attack** itself.
The only sanctioned way to add a tool is a **thin adapter**:

- wraps the tool's public CLI/SDK, pinned to an **exact** upstream version in its Dockerfile;
- takes a run request whose target is already scope-checked by the control plane;
- emits findings in the canonical schema plus evidence; does nothing else;
- carries an `adapter.yaml` manifest and a **contract test** against a recorded fixture.

No offensive payloads, exploit code or evasion techniques live in this repository. The control plane
executes nothing against a target itself; it launches adapters.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Implement our own attacks | Full control, no upstream drift | Enormous upkeep; safety/legal liability; duplicates the community | Against the product's purpose and values |
| Fat adapters that add attack logic | Fill tool gaps quickly | Blurs the orchestrate/implement line; harder to audit | Keep adapters thin; propose features upstream instead |
| Orchestrate thin adapters (**chosen**) | Safe, maintainable, legitimate, extensible | Depends on upstream; mapping/normalisation work is ours | Accepted; the normalisation *is* our value |

## Consequences

- Our engineering goes into the spine (findings model, dedup, evidence, scope, reporting, monitoring)
  and into mappings/adapters, not into exploits.
- Upstream changes are absorbed by version pinning + contract tests (a break fails CI, it does not
  corrupt findings), and by a deliberate, hand-reviewed pin bump.
- Upstream consolidation/abandonment is a real risk (many AI-security tools have been acquired); we
  mitigate with pinning, thin adapters that are cheap to replace, and preferring tools with
  permissive licences and healthy maintenance (see `docs/research/`).
- CONTRIBUTING.md and the adapter issue template encode this rule; CodeRabbit path-instructions flag
  adapters that add attack logic or reach hosts the control plane did not pass.
