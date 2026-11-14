# Spec 031 — mcp-scanner runs for real in the run sandbox

Sprint 7, story S7-4. Depends on: 025 (mcp-scanner adapter and parser), 012 (adapter execution),
002 (scope lock), 027 (the pattern this follows), 028 (target credentials). Packages:
`adapters/mcp-scanner/`, `api/`, `docs/`.

## Goal

Spec 025 gave Khandaq a parser for Cisco mcp-scanner's raw report, but its wrapper still expected a
report that was already there, and the registry did not list the adapter, so no run could be
queued for it.

When this spec is done, an operator picks **mcp-scanner** in the run launcher against an in-scope
`mcp_server` target. The worker runs the pinned mcp-scanner 4.8.5 image in the spec-012 sandbox.
The scanner connects to that one MCP server, lists its tools and checks their names and
descriptions with its bundled YARA rules. The run ends with:
- canonical findings (one per tool × analyzer × threat, as in spec 025);
- the scanner's raw report as sealed evidence;
- or a failed run, never a silent "clean" one.

Khandaq adds no rules and no detection logic. It runs the tool's own `remote` scan and translates
its report.

## User story

As an operator on an active engagement, I choose mcp-scanner and the in-scope MCP server, start the
run, and read which tools the scanner flagged, with its own report attached as evidence.

## Interface

- **Wrapper contract** (spec 012, as for garak): the run request arrives in `KHANDAQ_RUN_REQUEST`;
  the wrapper writes one uncompressed tar of its evidence directory to stdout and everything else
  to stderr; a non-zero exit means a failed run and no tar.
- **Scanner invocation**, the tool's public CLI and nothing else:
  `mcp-scanner --analyzers yara --format raw remote --server-url <target url>`, plus
  `--bearer-token <key>` when the target has a credential. The raw report is the scanner's stdout
  (4.8.5 ignores `--output` for a raw `remote` scan).
- **Target**: type `mcp_server` with an absolute `http`/`https` `url` and no fragment. The URL is
  passed to the scanner unchanged, so the request it makes is the URL the scope lock authorised
  (an `mcp_server` is matched by its exact URL).
- **Analyzers**: `yara` only, fixed. `params.analyzers`, if sent, must be `["yara"]` or `"yara"`;
  anything else fails the run before the scanner starts. The other analyzers (Cisco AI Defense,
  an LLM judge, VirusTotal) send the server's tool descriptions to a third party, which the
  sandbox's egress containment forbids and an engagement has not authorised.
- **Credential** (spec 028): the manifest sets `accepts_credential: true`.
  `KHANDAQ_TARGET_CREDENTIAL` becomes the scanner's `--bearer-token`. That flag is the tool's only
  interface for a token, so the key is an argument of a process inside the run's own container;
  it is never a `docker` argument, never in the request, and never in the wrapper's output.
- **Evidence**: `mcp-scanner-results.json` (the raw report, byte for byte) and `findings.jsonl`.
  Every finding cites the report.
- **Manifest and registry**: `adapter.yaml` gains `paces_requests: false` and
  `accepts_credential: true`; `khandaq.adapters.registry` registers `mcp-scanner` with the same
  values (the drift test keeps them equal), so `GET /api/adapters` lists it and runs can be queued.

## Behaviour

1. **Request.** A request that is missing, not JSON, or without a target fails the run (exit 2).
2. **Target.** A target that is not an `mcp_server`, or whose `url` is not an absolute `http(s)`
   URL, or carries a fragment, fails the run before the scanner starts.
3. **Analyzers.** Only `yara`; any other request for analyzers fails the run before the scanner
   starts.
4. **Scan.** The scanner runs once, with its console output on the wrapper's stderr and its raw
   report captured from stdout. Its environment carries neither the run request nor the
   credential variable, and no `MCP_SCANNER_*` or `VIRUSTOTAL_*` setting that could switch on
   another analyzer.
5. **Fail closed.** A non-zero exit, an empty report, or a report the spec-025 parser refuses
   (not JSON, nothing scanned, inconsistent counts) fails the run. No findings file and no tar are
   written: a scan that produced nothing trustworthy is a failed run, not zero findings.
   The same holds for a **partial scan**: if the report lists any item the tool failed or skipped,
   or one on which every analyzer errored, the run fails and names the items on stderr. The
   spec-025 parser still accepts such a report (it only refuses one in which nothing was scanned);
   the wrapper is stricter, because the findings of a partial scan would read as the whole picture.
6. **Clean scan.** A report in which every tool was scanned and none was flagged is a succeeded
   run with zero findings and the report as evidence.
7. **Rate cap.** mcp-scanner cannot hold a requests-per-minute limit (`paces_requests: false`), so
   an engagement whose rules of engagement cap the rate refuses it (spec 027).
8. **Scope and audit.** Nothing changes: the run passes the scope lock at creation and at claim,
   the sandbox's only route is the forwarder to the in-scope host, and the run is audited like any
   other.

## Acceptance criteria

- [x] `mcp-scanner` is a registered container adapter; the registry matches `adapter.yaml`; `GET
      /api/adapters` lists it.
- [x] The wrapper builds exactly the documented command for an `mcp_server` target and refuses
      other targets and other analyzers before the scanner starts.
- [x] With a credential the token is passed as `--bearer-token` and appears in no output of the
      wrapper; without one the flag is absent.
- [x] A successful scan writes the raw report and `findings.jsonl`, each finding citing the
      report, and emits the tar; a failed or untrustworthy scan writes neither.
- [x] A capped engagement refuses the adapter.
- [x] Manual e2e against a local, intentionally-vulnerable MCP server (synthetic, never a third
      party): a succeeded run with findings for the poisoned tool, the sealed report and a
      verifying ledger; with a required bearer key, success with the key and a failed run without
      it. The result is recorded in `TASKS.md`.

## Test cases

Adapter contract (`adapters/mcp-scanner/tests/test_contract.py`), with a fake in place of the
scanner process:
- `test_the_built_command_scans_the_in_scope_server_with_yara_only`;
- `test_unusable_targets_are_refused_before_the_scanner_runs`;
- `test_other_analyzers_are_refused_before_the_scanner_runs`;
- `test_the_scanner_environment_carries_no_request_credential_or_analyzer_setting`;
- `test_a_successful_scan_writes_the_report_and_findings_citing_it`;
- `test_a_clean_scan_succeeds_with_no_findings`;
- `test_a_failed_or_untrustworthy_scan_writes_no_findings`;
- `test_a_partial_scan_is_a_failed_run_not_a_clean_one`;
- `test_the_credential_is_the_bearer_token_and_is_in_no_output`;
- `test_main_reads_the_request_from_the_environment_and_emits_a_tar`;
- `test_main_emits_nothing_on_stdout_when_the_run_fails`.

API (`api/tests/test_adapter_registry.py`):
- the drift test covers `mcp-scanner`;
- `test_mcp_scanner_is_a_registered_container_adapter`;
- `test_the_adapter_list` includes it.

Security: the egress e2e of spec 012 is unchanged and still passes; the wrapper passes no host but
the target's URL to the scanner.

## Known limit of the pinned tool

mcp-scanner 4.8.5 calls `tools/list` once and does not follow `nextCursor`. On an MCP server that
paginates its tool list, tools on later pages are not scanned, and the raw report does not say so:
the wrapper cannot detect it, and enumerating pages itself would be scanning logic, which an
adapter must not carry (ADR-0001). A run against such a server covers the first page only. It is
fixed by a scanner version that paginates, taken as a deliberate pin bump with the contract test.

## Out of scope

- The scanner's `prompts`, `resources` and `instructions` scans: 4.8.5 prints no raw report for
  them. A later spec, once the tool does or the parser reads their summary format.
- The `api`, `llm`, `virustotal`, `behavioral` and package analyzers, and stdio or config scans:
  they need a third party, source code or a local process, none of which is a network target the
  scope lock authorises.
- A bundled demo MCP target for `make demo`: the manual e2e uses a local scratch server; bundling
  one is a follow-up.
- Refusing an adapter that does not fit the target's type before the run is queued (today the
  wrapper refuses it and the run fails, as for garak).
- PyRIT and promptfoo in the sandbox (specs 029, 030).
