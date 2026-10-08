# Spec 012 — Adapter execution: egress-contained containers on the worker

Sprint 4, story S4-6 (closes R1). Depends on: 002, 004, 005, 006, 009, 010. Packages: `api/`
(adapters, runs, worker, egress forwarder), `adapters/`, `deploy/`, `.github/workflows/`.

## Goal

An authorised run of garak, PyRIT or promptfoo actually executes the pinned tool, in its own
container on the worker, against the one in-scope target. The container can reach nothing else. Its
findings are normalised, its evidence is retained and sealed, and the run's record survives any
failure. Until this spec, spec 005's `DockerRunner.run` raised `NotImplementedError`, the API knew
only the in-process `echo` adapter, and the adapters parsed a report nothing had produced.

## User story

As an operator, I launch a garak run against the bundled vulnerable target from the console, and
minutes later I see its deduplicated findings and sealed evidence. An adapter that tries to reach
any other host fails to connect.

## Interface

- **Adapter I/O contract (v2, replaces spec 005's mounts).**
  - **Input:** the run request JSON in the env var `KHANDAQ_RUN_REQUEST`, the same document
    `build_run_request` builds today. It is passed through a mode-0600 `--env-file`, never on a
    command line, where `ps` would show it.
  - **Output:** the adapter writes `findings.jsonl` and its evidence files to `/evidence`, a tmpfs.
    On exit it writes one **uncompressed tar of `/evidence`** to stdout and nothing else; the tool's
    own output goes to stderr.
  - **Why:** the container needs no host path or volume. With the Docker socket (shape A), `-v`
    paths are resolved on the host, not in the worker container, which made spec 005's mount
    contract unusable.
  - Exit 0 means success. Anything else fails the run, and its stderr tail is recorded.
- **Runner.** `DockerRunner.run(request) -> {"evidence": [...], "findings": [...]}` runs these
  steps through an injected `DockerCli` (subprocess by default):
  1. `docker network create --internal khq-net-<run>` — no route out.
  2. Start the **egress forwarder**, `khq-fwd-<run>`, on the egress network.
  3. `docker network connect --alias <target host> khq-net-<run> khq-fwd-<run>`.
  4. `docker create` the adapter, `khq-run-<run>`, on the internal network only, with the spec 005
     hardening (read-only rootfs, `--cap-drop ALL`, `no-new-privileges`, user `nobody`, memory,
     CPU and pid limits) and tmpfs `/tmp` and `/evidence`.
  5. `docker start -a` with a timeout, reading stdout up to a size cap.
  6. Always remove the containers and the network afterwards.
- **Egress forwarder** (`khandaq.egress_forwarder`, stdlib only).
  - A TCP forwarder that listens on the target's port and connects only to the one address the
    worker resolved and checked.
  - It runs with `python -c` from the module's source, so any image with Python 3 works. The default
    is the deployment's own API image (`KHANDAQ_FORWARDER_IMAGE`).
  - It is hardened like the adapter. `net.ipv4.ip_unprivileged_port_start=0` lets `nobody` bind
    443.
- **Settings:**

  | Setting | Purpose | Default |
  |---|---|---|
  | `KHANDAQ_FORWARDER_IMAGE` | Image the forwarder runs from | required for Docker runs |
  | `KHANDAQ_ADAPTER_EGRESS_NETWORK` | Network from which targets are reachable | `bridge` |
  | `KHANDAQ_ADAPTER_TIMEOUT_SECONDS` | Run timeout | 3600 |
  | `KHANDAQ_ADAPTER_OUTPUT_LIMIT_MB` | Cap on the stdout tar | 256 |
  | `KHANDAQ_EVIDENCE_DIR` | Retained evidence bytes | `/var/lib/khandaq/evidence` |
  | `KHANDAQ_ADAPTERS_DIR` | Manifests the registry loads | the packaged `adapters/` |
- **Scope helper.** `scope.network_endpoint(target_type, spec) -> (host, port)` derives the one
  endpoint a run may reach, from the same canonical view the scope lock uses.
- **Run states:** unchanged (`queued → running → succeeded|failed`, or `rejected`). Container runs
  are created `queued` and executed by the worker (ADR-0015). Builtin adapters still run in-process.
- **Registry.** Builtins plus every valid `adapter.yaml` under `KHANDAQ_ADAPTERS_DIR`. An invalid
  manifest is logged and skipped, never half-loaded.

## Behaviour

1. **Creation (API).** The scope lock runs exactly as in spec 005; a rejection is recorded and
   audited. An allowed **container** run is committed `queued` with `run.queued` audited, and the
   API returns 201. The builtin echo adapter keeps its synchronous path.
2. **Claim (worker).**
   - The worker claims the oldest queued run with `FOR UPDATE SKIP LOCKED`.
   - It **re-evaluates the scope lock against the current scope and time**, because the engagement
     may have been paused, the scope narrowed or the window closed since creation. A refusal is
     recorded as `rejected` with `run.rejected`.
   - Otherwise it records `running` with `run.started` and **commits before launching**.
3. **Endpoint.**
   - `network_endpoint` must give exactly one host and port.
   - The worker resolves the host itself. It refuses an IP-literal target, and an address that is
     loopback, link-local (cloud metadata), multicast or unspecified.
   - Every refusal fails the run with a reason (`run.failed`), and nothing is launched.
4. **Containment (ADR-0009).**
   - The adapter is only on an `--internal` network. Its target hostname resolves, via the alias,
     to the forwarder, which relays TCP to the pinned address. TLS passes through end to end.
   - Any other host has no route. This is a **negative test against a real daemon in CI**: a decoy
     server on the same egress network is unreachable from the adapter.
5. **Output.**
   - The stdout tar must contain only regular files with flat names (`[A-Za-z0-9._-]{1,128}`), at
     most 1000 of them, within the size cap. Anything else fails the run.
   - Evidence hashes are computed by the worker, never taken from the adapter.
   - Each file other than `findings.jsonl` becomes an evidence item. Its `local_id` is the file
     name, it is retained write-once at `KHANDAQ_EVIDENCE_DIR/<engagement>/<run>/<sha256>`, and it
     is then sealed (spec 004 / ADR-0014).
   - Findings refer to evidence by file name (`_evidence_local`).
6. **Results** are persisted exactly as in spec 005: lock, seal, normalise, cross-run dedup. A
   failure at any step is recorded `failed` with `run.failed` in a fresh transaction.
7. **Recovery.** At startup the worker marks runs that have been `running` for longer than the
   timeout plus a margin as `failed` ("worker lost the run") with `run.failed`. A run is never left
   running forever.
8. **Adapters invoke their tools.** Each `wrap.py` reads the request and runs the pinned tool's
   public CLI or SDK against `target.spec.base_url` / `model`, with the params the manifest
   documents. It then parses the report (spec 006/009/010, fail closed) and emits the tar. Adapters
   add **no payloads**: probes and attacks are the upstream tool's own.
9. **Mapping seeds (S2-3).** `mappings/builtin.json` covers every rule id the three R1 adapters can
   emit, with sources cited.

## Acceptance criteria

- [x] `DockerRunner` command sequence, cleanup on every failure path, IP and endpoint refusals, and
      tar validation are unit-tested with a fake `DockerCli`.
- [x] CI `e2e` job (real daemon):
  - a probe adapter reaches the vulnerable target through the forwarder;
  - it **cannot** reach a decoy on the same egress network, or the internet;
  - its tar output is read back.
- [x] Container runs are queued by the API and executed by the worker, which re-checks the scope at
      claim time (test: scope narrowed after queueing → `rejected`).
- [x] Stale `running` runs are failed at worker start (test).
- [x] Evidence bytes are retained write-once and sealed; the ledger verifies.
- [ ] garak, PyRIT and promptfoo adapters invoke their tool, and contract tests assert the built
      command. A CI e2e run of the garak image against the vulnerable target produces schema-valid
      findings. (garak: done in spec 027, with the e2e run manual because the image is several GB;
      PyRIT and promptfoo follow in their own specs.)
- [ ] Mapping seeds cover the R1 adapters' rule ids (test: no `unmapped` for a known rule).

## Test cases

- Unit (`api/tests/test_docker_runner.py`): command sequence; network and container removed on
  timeout, non-zero exit and oversize output; refusals (IP literal, link-local, two ports); tar
  validation (path traversal, symlink, too many files).
- Integration (`api/tests/test_worker.py`): queue → claim → execute with a fake runner; scope
  re-check; stale recovery; concurrent claims take different runs.
- E2E (`api/tests/e2e/`, marked `docker`, skipped without a daemon): egress containment with a
  probe image; garak against the vulnerable target.
- Security: the decoy negative test; findings and evidence hashes come from the worker, not the
  adapter.

## Out of scope

- Evidence upload to the object store and envelope encryption (ADR-0006). Bytes are retained on the
  worker volume for now.
- Multi-node runners (R3).
- Kubernetes or VM isolation (ADR-0009 alternative).
- IP-literal targets.
- Campaign scheduling (R2, ADR-0008).
