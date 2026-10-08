# Spec 027 — garak runs for real in the run sandbox

Sprint 6, story S6-4. Depends on: 006 (garak adapter), 012 (adapter execution), 002 (scope lock),
026 (console setup). Packages: `adapters/garak/`, `api/`, `web/`, `deploy/`, `docs/`.

## Goal

Spec 012 built the sandbox: a per-run internal network, an egress forwarder that answers only as the
in-scope target, and a hardened adapter container whose evidence comes back as a tar on stdout.
Until now no real adapter used it. The garak wrapper still expected a report that was already
there, and the registry only knew the in-process `echo` adapter.

When this spec is done, an operator picks **garak** in the console's run launcher against an
OpenAI-compatible target the engagement authorises, for example the bundled vulnerable target or a
self-hosted Ollama. The worker then runs the pinned garak 0.17.0 image in the sandbox. garak's
published probes go to that one target, and the run ends with:
- canonical findings;
- garak's report and hit log as sealed evidence;
- or a failed run, never a silent "clean" one.

Khandaq adds no probes or prompts. It selects garak's own published probes by name.

PyRIT, promptfoo and mcp-scanner follow the same pattern in their own specs, one at a time.

## User story

As an operator on an active engagement, I choose garak and the in-scope endpoint, start the run, and
read the findings with garak's own report attached as evidence. I do this without handling a report
file myself.

## Interface

- **Wrapper contract** (`adapters/garak/wrap.py`, spec 012 contract v2):
  - **Input:**
    - the run request in `KHANDAQ_RUN_REQUEST`, with a `/run-request.json` fallback for local use;
    - `target.type` is `llm_endpoint` or `agent`;
    - `target.spec.url` (or `base_url`) is an absolute `http(s)` URL ending in `/chat/completions`;
    - `target.spec.model` is required;
    - `params.probes` is optional: a list, or a comma-separated string, of at most 10 garak probe
      names (a family `promptinject` or a class `promptinject.HijackHateHumans`). The default is a
      small set that finishes in minutes on a CPU model.
  - **Invocation:**
    `python -m garak --target_type openai.OpenAICompatible --target_name <model>
    --generator_option_file <tmp>/generator.json --probes <list> --generations 1
    --parallel_attempts 1 --report_prefix khandaq`.
    - The option file is `{"openai": {"OpenAICompatible": {"uri": <url minus chat/completions>}}}`.
    - `XDG_DATA_HOME`, `XDG_CACHE_HOME` and `XDG_CONFIG_HOME` point under `/tmp`.
    - `OPENAICOMPATIBLE_API_KEY` is a placeholder. Per-run credentials are a later spec.
    - garak's console output goes to stderr.
  - **Output:** `findings.jsonl`, `garak-report.jsonl` and `garak-hitlog.jsonl` (when garak wrote
    one), as one tar on stdout. Every finding references both evidence files.
- **Manifest flag** `paces_requests` (`AdapterManifest` and `adapter.yaml`, default `false`): the
  adapter holds a requests-per-minute limit itself.
  - `echo` sets it, because it sends nothing to the target.
  - garak does not set it: it sends one request at a time but has no limiter.
- **Registry**: `garak` is registered. Its manifest mirrors `adapters/garak/adapter.yaml`, and a
  drift test keeps the two equal. `all_manifests()` lists every adapter.
- **API**:
  - `GET /api/adapters` (any signed-in user) returns
    `[{name, version, phases, frameworks, builtin, paces_requests}]`;
  - `POST /api/engagements/{id}/scope-check` accepts an optional `adapter`.
- **Console**: the run launcher has an adapter select fed by `GET /api/adapters`. When garak is
  chosen it adds an optional "garak probes" field, sent as `params.probes`. The pre-flight is checked
  for the chosen adapter.
- **Image**: unchanged apart from the wrapper. It still runs as `nobody` on a read-only root
  filesystem with tmpfs `/tmp` and `/evidence` (spec 012).

## Behaviour

1. **One target, one path.** garak calls `<uri>chat/completions`. Because the URI is the target URL
   minus that suffix, the request garak makes is exactly the URL the scope authorised. A target URL
   that does not end in `/chat/completions` is refused before garak starts (exit 2, no findings).
   The sandbox network still reaches only the forwarder for that host (spec 012).
2. **Fail closed.** The run fails (exit 2) and writes no `findings.jsonl` and no tar when:
   - the request is unusable;
   - a probe name does not match the probe-name pattern, or more than 10 are given;
   - garak exits non-zero or writes no report;
   - the report is incomplete or malformed (spec 006 parser).

   The worker records a failed run (spec 012).
3. **Rate limit.** The scope lock already requires a declared `rate_per_minute` within
   `roe.max_requests_per_minute` (spec 002). An adapter with `paces_requests: false` cannot
   guarantee it, so when the scope's RoE sets a cap, the run is refused with an audited
   `run.rejected`:
   - at creation (`create_run`, the campaign scheduler's `queue_run`);
   - at the worker's claim;
   - and a campaign for such an adapter is refused at creation (422, `campaign.rejected`).

   The pre-flight with `adapter` gives the same answer. Without a cap, garak runs one request at a
   time.
4. **garak's report shape.** A real garak 0.17.0 run appends one `digest` record after
   `completion`. The parser accepts exactly one such record and still refuses anything else after
   `completion` (spec 006's guard against concatenated reports).
5. **Evidence.** garak's report and hit log become evidence with worker-computed hashes and are
   sealed in the ledger (spec 012). Each finding cites them.
6. **No new attack content.** The wrapper passes garak probe names only. It adds no prompts,
   payloads or detectors of its own (CLAUDE.md, ADR-0001).

## Acceptance criteria

- [x] The wrapper builds the garak command above from the request; contract tests assert the
      command, the generator options and the environment, and that it emits a tar of findings and
      evidence.
- [x] Unusable targets, malformed probe selections, a failed garak, a missing report and an
      incomplete report each end in a non-zero exit with no findings and nothing on stdout.
- [x] `garak` is registered and matches `adapter.yaml` (drift test); `GET /api/adapters` lists it.
- [x] With an RoE rate cap, a garak run is rejected and audited at creation and at claim, a garak
      campaign is refused, and the pre-flight with `adapter: "garak"` says why; `echo` is unaffected.
- [x] The console launcher offers the registered adapters and sends the garak probe list; the
      pre-flight is checked for the chosen adapter.
- [x] The garak image, run by the real `DockerRunner` against the bundled vulnerable target, ends
      in a succeeded run with schema-valid findings and sealed evidence (manual e2e, recorded in
      `TASKS.md`).
- [x] CapRover docs: running garak against the demo target and against an internal-only Ollama app.

## Test cases

Adapter contract (`adapters/garak/tests/test_contract.py`):
- `test_the_built_command_targets_the_in_scope_endpoint_only`;
- `test_a_successful_run_writes_findings_with_evidence`;
- `test_requested_probes_are_passed_by_name`;
- `test_malformed_probe_selections_are_refused_before_garak_runs`;
- `test_unusable_targets_are_refused_before_garak_runs`;
- `test_a_failed_garak_run_writes_no_findings`;
- `test_main_reads_the_request_from_the_environment_and_emits_a_tar`;
- `test_main_emits_nothing_on_stdout_when_the_run_fails`.

API (`api/tests/test_adapter_registry.py`):
- the manifest/`adapter.yaml` drift test;
- `test_adapter_refusal_for_a_rate_cap`;
- `test_the_adapter_list`;
- `test_a_capped_engagement_refuses_garak_with_an_audit_entry` (run, campaign and pre-flight);
- `test_garak_queues_without_a_cap_and_is_rechecked_at_claim`.

Web (`web/src/__tests__/engagement.test.tsx`): garak runs with the chosen probes, checked for that
adapter; the rate-cap refusal is shown and Run stays disabled.

## Out of scope

- PyRIT, promptfoo and mcp-scanner execution: each gets its own spec on this pattern.
- Per-run target credentials (an ephemeral key in the run request): a later spec. Until then only
  targets that need no key, or accept any key, can be tested.
- A requests-per-minute limiter for garak, for example a pacing forwarder: a later spec. Until then
  capped engagements refuse garak.
- A CI job that runs the garak image end to end. The image is several GB, so the e2e check is
  manual for now (acceptance criterion above).
