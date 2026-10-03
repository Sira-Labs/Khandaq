# Spec 025 — Cisco mcp-scanner adapter

Sprint 6, story S6-1. Depends on: 005 (adapter contract), 012 (container execution), 020 (mapping
table). Packages: `adapters/mcp-scanner/`, `core/khandaq-core/mappings/`, `api/tests/`,
`.github/workflows/`, `docs/`.

## Goal

Phase 07 (agentic, MCP and A2A) gets its first adapter. When this spec is done:
- `adapters/mcp-scanner/` wraps Cisco's **mcp-scanner** (Apache-2.0), pinned to **4.8.5**.
- Its wrapper translates the tool's raw JSON report (`mcp-scanner --format raw`) into canonical
  findings: one per threat that one analyzer reported on one MCP tool, prompt or resource.
- A contract test runs the wrapper against a recorded fixture and checks every finding against
  the canonical schema, so an upstream format change that breaks the mapping fails CI.
- The release workflow publishes `ghcr.io/sira-labs/khandaq-adapter-mcp-scanner`.
- The core mapping table gains the mcp-scanner threat families that have an unambiguous framework
  id, and the drift test covers the wrapper.

The scope lock already supports the two target types this phase needs, `mcp_server` (an exact
URL) and `agent` (host and path, like `llm_endpoint`). It is not changed here. This spec adds the
negative tests that pin how those types are matched.

As with garak, PyRIT and promptfoo, invoking the tool inside the run sandbox is spec 012's
remaining part. Until then the wrapper reads a report that is already in the evidence directory
and fails closed when there is none.

## User story

As a red-team operator testing an MCP server I am authorised to test, I get mcp-scanner's tool
poisoning and prompt injection findings in the same inbox and report as my garak findings, mapped
to OWASP Agentic and ATLAS ids.

## Interface

- **Manifest** `adapters/mcp-scanner/adapter.yaml`: `name: mcp-scanner`, `version: "4.8.5"`, image
  `ghcr.io/sira-labs/khandaq-adapter-mcp-scanner:4.8.5`, phase `07-agentic-mcp`, frameworks
  `owasp-agentic`, `owasp-llm-2026`, `atlas`, and the severity table `high`/`medium`/`low`/`info`.
- **Image**: `python:3.12-slim` with `cisco-ai-mcp-scanner==4.8.5` and the wrapper.
- **Report**: `mcp-scanner-results.json` in the evidence directory, in the tool's raw format:

  ```json
  {"server_url": "...", "requested_analyzers": ["yara", "api"],
   "scan_results": [{"status": "completed", "is_safe": false, "item_type": "tool",
     "tool_name": "read_file", "tool_description": "...",
     "findings": {"yara_analyzer": {"severity": "HIGH", "threat_names": ["TOOL POISONING"],
       "threat_summary": "...", "total_findings": 1, "mcp_taxonomies": [...]}}}]}
  ```

  Prompts carry `prompt_name` and resources carry `resource_uri`/`resource_name` instead of
  `tool_name`.
- **Finding** (one per item × analyzer × threat name):
  - `rule_id`: `mcp-scanner.<threat>`, where `<threat>` is the threat name lower-cased with every
    run of other characters replaced by `-` (`TOOL POISONING` and `PROMPT_INJECTION` become
    `tool-poisoning` and `prompt-injection`, so the LLM and API analyzers' spellings
    deduplicate).
  - `severity`: the analyzer's severity, lower-cased; `SAFE` with findings counted is `info` (see
    Behaviour 2).
  - `locations`: one logical location `<item_type>:<name>` (`tool:read_file`).
  - `source`: `{"tool": "mcp-scanner", "version": "4.8.5", "native_severity": ..., }`.
  - `title`: `mcp-scanner: <threat> in <item_type> <name> — <threat_summary>`, at most 200
    characters.
  - `x-khandaq.phase` is `07-agentic-mcp`. `x-khandaq.mappings` holds the wrapper's ids for the
    family, or none when the family is not curated. The API applies the core table at ingest
    either way (spec 020).
- **Mapping table** additions (`core/khandaq-core/mappings/builtin.json`):

  | Key | ATLAS | OWASP LLM 2025 | OWASP LLM 2026 | OWASP Agentic | NIST AI RMF |
  |---|---|---|---|---|---|
  | `mcp-scanner.prompt-injection` | AML.T0051 | LLM01 | LLM01 | — | MEASURE-2.7 |
  | `mcp-scanner.data-exfiltration` | AML.T0057 | LLM02 | LLM02 | — | MEASURE-2.10 |
  | `mcp-scanner.code-execution` | — | — | — | ASI05 | — |
  | `mcp-scanner.tool-poisoning` (exists) | AML.T0053 | — | — | ASI04 | — |

  The ATLAS, OWASP LLM and NIST ids are the ones the table already uses for the same weakness
  from other tools (`echo.inject`, `echo.leak`).

  There is no `mcp-scanner` default: an uncurated threat is `unmapped`, as for garak.

## Behaviour

1. **Parse.** The wrapper reads the report and emits one finding for each threat name of each
   analyzer entry that counted findings (`total_findings > 0`), on each scanned item.
2. **Severity.** The raw format keeps one severity per analyzer per item, the highest of its
   findings, and it only promotes to `HIGH`, `MEDIUM` or `LOW`. Findings the tool rated `INFO` (or
   could not rate) are counted but leave the entry at `SAFE`. So:
   - `HIGH`, `MEDIUM` and `LOW` map to `high`, `medium` and `low`;
   - `SAFE` with `total_findings > 0` maps to `info`;
   - every threat of one entry shares that entry's severity.
3. **Not findings.**
   - An entry with `total_findings: 0` (the tool's `SAFE`, "No threats detected").
   - An entry the tool marks `"status": "error"` (severity `UNKNOWN`): that analyzer failed on that
     item, so it found nothing.
   - An entry marked `partial` still yields its counted findings.
   - An item marked `failed` or `skipped` yields no findings, even when it lists threats; its
     entries are still validated.
4. **Fail closed.** The wrapper raises `ReportError`, and `main` exits 2 without writing
   `findings.jsonl`, when any of these hold. A run without a trustworthy report must surface as a
   failed run, never as "no findings".
   - The report is empty, not JSON, not an object, or has no `scan_results` list.
   - `scan_results` is empty: nothing was scanned.
   - An item or its `findings` is not an object, a severity is not one of the tool's levels, or a
     count is not a non-negative integer.
   - An entry contradicts itself: a `HIGH`/`MEDIUM`/`LOW` severity with no findings counted, or
     findings counted with no threat names.
   - No item was actually scanned: every item is `failed` or `skipped`, or every analyzer entry of
     every item errored.
5. **Scope.** Unchanged and server-side. The run's single egress endpoint is derived from the
   target the scope lock checked (spec 012):
   - `mcp_server` targets match an allow rule by exact URL. A different scheme, port, path, user
     info or host spelling is refused.
   - `agent` targets match by host and permitted paths, like `llm_endpoint`.

## Acceptance criteria

- [x] `adapters/mcp-scanner/` has a manifest that passes `validate_manifests.py`, a Dockerfile
      pinned to `cisco-ai-mcp-scanner==4.8.5`, a Makefile with `build` and `contract-test`, and the
      wrapper.
- [x] The contract test parses the recorded fixture into schema-valid findings with the expected
      rule ids, severities (including `info`), locations and mappings, and skips safe and errored
      entries.
- [x] Every fail-closed case in Behaviour 4 raises `ReportError`; `main` exits non-zero and writes
      no findings file for a missing, empty or untrustworthy report, and writes one for a good one.
- [x] The core table has the three new entries, and the drift test covers the wrapper's families.
- [x] Negative scope tests pin exact-URL matching for `mcp_server` (scheme, port, path, user info,
      host case) and host-and-path matching for `agent`, plus the `mcp_server` network endpoint.
- [x] The release workflow builds and pushes `khandaq-adapter-mcp-scanner`.

## Test cases

Contract (`adapters/mcp-scanner/tests/test_contract.py`, run by CI's adapters job): fixture →
findings (count, schema, rule ids, severities, locations, mappings); safe, errored and partial
entries; prompts and resources; threat-name slugs; each fail-closed case; `main` with a missing,
empty and good report.
Integration (`api/tests/test_mapping_drift.py`): every wrapper id is in the core table for
`mcp-scanner.<family>`, and an uncurated threat is unmapped.
Security (`api/tests/test_scope_eval.py`): `mcp_server` refuses `http://`, another port, another
path, `..` segments, user info and a different host spelling; `agent` refuses another host and
another path; `network_endpoint("mcp_server", …)` is the URL's host and port.

## Out of scope

- Running mcp-scanner inside the sandbox: spec 012's remaining part, with the other adapters.
- Choosing analyzers. The `api` analyzer (Cisco AI Defense), the LLM judge and VirusTotal send tool
  descriptions to a third party. Under the engagement's data-handling rules they stay off, so the
  default once execution lands is `--analyzers yara`. The parser accepts every analyzer's entries,
  for an operator who enables one with the client's consent.
- Scanning local MCP client configs or stdio servers: not a network target the scope lock
  can authorise.
- A2A (agent-to-agent) testing: phase 07's R2 part.
- Creating `mcp_server` or `agent` targets in the console: targets are created through the API
  today; a console target form is a later console spec.
