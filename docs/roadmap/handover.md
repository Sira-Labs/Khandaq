# Khandaq — handover

*Last updated 2026-10-10. A standing orientation for whoever picks up the project next — a new
engineer, or a fresh Claude Code session. It says what Khandaq is, where the code is, how to build
and test it, what is done, what is next, and the decisions still owed to the owner. It does not
replace the specs or the ADRs; it points at them.*

## 1. What Khandaq is

Khandaq is a self-hostable platform for **authorised** AI red-team engagements. It does not invent
attacks. It **orchestrates** published, open-source testing tools (garak, PyRIT, promptfoo,
Cisco mcp-scanner), runs each in an isolated container that can reach only the one target an
engagement authorises, **normalises** every tool's output into one canonical finding schema (a SARIF
superset), **deduplicates** across tools and runs, **maps** each finding to the security frameworks
(MITRE ATLAS, OWASP LLM 2025 + 2026, OWASP Agentic, NIST AI RMF), seals the raw evidence in an
append-only hash-chained ledger, and watches for regression over time with scheduled campaigns and
alerts.

The product is the trustworthy spine around those tools, not the tools: the **scope lock** (no run
ever reaches an out-of-scope target), the **audit log** (every privileged action recorded,
append-only), and the **evidence ledger** (tamper-evident, verifiable offline). Read
`docs/VISION.md` and `docs/architecture/01`–`04` before changing design. `CLAUDE.md` is the
working contract; `CONTRIBUTING.md` has the branch and PR rules.

### The one rule that shapes every change

Khandaq orchestrates tools; it does not implement novel attacks. **Do not add offensive payloads,
exploit code, or evasion techniques to this repository.** An adapter wraps a tool's public
interface and translates its output — nothing more. If a change would weaken the scope lock, the
audit trail, or evidence integrity, stop and raise it. This is stated in `CLAUDE.md`,
`SECURITY.md` and ADR-0001, and it is enforced in code and in CI (scope-lock unit tests, the
append-only audit trigger, the mapping drift test).

## 2. Current state (2026-10-10)

**R1 (the spine) is complete** and **R2 (coverage) is well advanced.** An authorised engagement
runs end to end today: sign in via OIDC → create and scope an engagement → launch a run →
scope-locked, egress-contained container executes a real tool → findings normalised, deduped and
framework-mapped → evidence sealed and verifiable → management + technical report exported and
re-verifiable → scheduled campaigns diff runs over time and alert on regression.

Implemented specs: **001–027** (see `TASKS.md` for the per-spec decision log, and `docs/specs/` for
each). Sprints 1–6 are done. All work lands on the branch `claude/kind-planck-xd0el7`, one PR per
spec, merged by the owner.

### Adapters — execution status

The distinction that matters right now is **"parser done" vs. "runs the real tool in the sandbox."**
Every adapter has a pinned Dockerfile, a manifest, an output parser and a contract test against a
recorded fixture. Only some have been wired to invoke the real upstream tool inside the spec-012
sandbox.

| Adapter | Pinned version | Parser + contract test | Runs in the sandbox | Notes |
|---|---|---|---|---|
| `echo` | — (in-process) | ✅ | ✅ | Sends nothing to the target; demo/tests; `paces_requests: true`. |
| `garak` | 0.17.0 | ✅ | ✅ (spec 027) | Manual e2e verified 2026-10-08 against the bundled vulnerable target. |
| `pyrit` | 1.1.0 | ✅ | ❌ **pending** | Sandbox-execution wrapper not completed — see §6. |
| `promptfoo` | 0.118.0 | ✅ | ❌ **pending** | Sandbox-execution wrapper not completed — see §6. |
| `mcp-scanner` | 4.8.5 | ✅ | ❌ **pending** | Sandbox-execution wrapper not yet written (own spec, per spec 027 "out of scope"). |

garak is the reference implementation of the spec-012 contract v2. The remaining three follow the
**same pattern** — read the run request from `KHANDAQ_RUN_REQUEST`, invoke the tool against the one
in-scope endpoint, emit a tar of findings + evidence on stdout, fail closed — each in its own spec.

## 3. Repository map

```
core/        Rust workspace (integrity-critical logic)
  khandaq-core   findings model, canonicalisation, fingerprint/dedup, severity,
                 framework mapping, hash-chained ledger
  khandaq-cli    `khandaq` binary (validate / normalize / ledger-verify offline)
  khandaq-py     PyO3 wheel `khandaq_core`, imported by the API
api/         Python 3.12+ FastAPI control plane (uv)
  src/khandaq/   auth (OIDC BFF), authz, engagements, scope lock, runs, findings,
                 campaigns, reports, worker, adapter host + registry + manifests
  tests/
adapters/    one dir per tool: thin wrapper + Dockerfile (pinned) + adapter.yaml manifest
  _tooling/      shared build helpers (CA-bundle base image for the agent proxy)
  echo/ garak/ pyrit/ promptfoo/ mcp-scanner/
web/         Vite + React 19 + TanStack Query + Tailwind v4 SPA (pnpm)
deploy/      compose bundle, Caddyfile, CapRover guide + captain-definitions,
             Keycloak realm exports, smoke.py, targets/vulnerable-llm/ (demo target)
docs/        VISION, architecture/, adr/, specs/, research/, roadmap/
TASKS.md     backlog + per-spec decision log (read this for "why")
```

Key architecture decisions live in `docs/adr/` (0001–0017). Add a new ADR rather than silently
deviating from one.

## 4. Build, test, run

All from the repo root unless noted. `make lint` and `make test` run everything; the per-language
subsets are faster while iterating.

- **Rust core:** `cd core && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
- **Python API:** `cd api && uv sync --extra dev && uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy`
- **Bindings (after a core change):**
  `cd core/khandaq-py && VIRTUAL_ENV=../../api/.venv ../../api/.venv/bin/maturin develop --release && ../../api/.venv/bin/pytest -q`
- **Web:** `cd web && pnpm install --frozen-lockfile && pnpm lint && pnpm build`
- **Adapters:** each has `make build` (image) and `make contract-test` (parser against the recorded
  fixture — the guard that an upstream change which breaks the mapping fails CI).
- **Demo suite:** `make demo` runs a suite against the bundled intentionally-vulnerable local target
  (never a third party) and prints the unified report.

### Running a tool for real (local e2e)

A real adapter run needs a Docker daemon (the sandbox builds a per-run `--internal` network with an
egress forwarder aliased as the target host). This is why the garak e2e is a **manual** acceptance
step, not a CI job — the image is ~2.8 GB. The procedure that verified garak on 2026-10-08:

1. Build the pinned adapter image (`cd adapters/garak && make build`).
2. Bring up the bundled vulnerable target (`deploy/targets/vulnerable-llm/`) or a self-hosted Ollama.
3. Drive a run through the API/worker (`DockerRunner`) against that in-scope endpoint.
4. Confirm: a **succeeded** run, schema-valid findings, two sealed evidence files, a verifying
   ledger. A run that produces nothing trustworthy must **fail**, never report a silent "clean".

CapRover deployment notes (internal-only demo target or Ollama) are in `deploy/caprover.md`.

### Environment notes for this cloud session

- Outbound HTTPS goes through the agent proxy; pip/docker builds need the CCR CA bundle
  (`/root/.ccr/ca-bundle.crt`) baked into the base image — see `adapters/_tooling/`.
- Install the **CPU-only** torch (`torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu`)
  before any tool that pulls it, or the image balloons with CUDA libs it will never use (this is
  what dropped the garak image from 10.4 GB to 2.8 GB — see TASKS.md S6-4).

## 5. Deployment state

- **Images:** `release.yml` publishes control-plane (`khandaq-api`, `khandaq-web`) and adapter
  images to GHCR on push to `main`; each adapter image is tagged with its manifest version
  (e.g. `khandaq-adapter-garak:0.17.0`) and the demo target is published too (fixed in #64).
- **Staging:** CapRover, apps named `khandaq-stg-<role>` on `https://khandaq-stg.siralabs.org`.
- **Auth:** real OIDC via Keycloak (BFF, `__Host-` session cookie, CSRF, revocable API tokens).
  Realm exports in `deploy/keycloak/`; import with **Create realm → Resource file** (full import),
  not partial.
- **Evidence:** AES-256-GCM at rest, envelope-wrapped under a KEK from `KHANDAQ_EVIDENCE_KEY`,
  write-once in the S3 object store (RustFS) or local evidence dir. **Losing the key makes evidence
  unreadable** — its backup is an open owner item (ADR-0006).

## 6. The immediate blocker, stated plainly

The next scheduled work is wiring **PyRIT** and **promptfoo** to run their real tools in the
spec-012 sandbox, the same way garak was wired in spec 027. The parsers, fixtures and contract
tests already exist; what remains for each is the ~40-line invoke function (read the request, build
the tool's command/SDK call against the one in-scope endpoint, emit the evidence tar, fail closed).

During this session, **attempts to author that PyRIT/promptfoo sandbox-execution wrapper code were
repeatedly stopped by a server-side safety classifier** (independent of the model, and the cause of
an automatic model fallback on the stopped turns). The work was not completed and was not worked
around. Clean paths forward, none of which involve circumventing the classifier:

1. A human developer adds the per-adapter invoke function directly. Everything else for these
   adapters (parser, manifest, Dockerfile, fixtures, tests) is in place; garak's `wrap.py` is the
   worked reference for the contract.
2. Resolve the false-positive with Anthropic. A draft to Anthropic describing the block on
   authorised defensive work has been prepared in the owner's Gmail (needs a recipient and a
   signature before sending).
3. Keep building the non-adapter roadmap items (§7), which are unaffected.

Record this honestly in any status update: garak runs for real; PyRIT and promptfoo do not yet, and
the reason is the above, not a code defect.

## 7. What's next (roadmap)

See `docs/roadmap/sprints.md` for the full sprint plan and forecast. In priority order from here:

**Finish adapter execution (spec-027 pattern, one spec each):**
- Spec 028 — PyRIT runs in the sandbox (PyRIT 1.1.0 Python API; built-in rate limiter, so it can set
  `paces_requests: true`).
- Spec 029 — promptfoo runs in the sandbox.
- A later spec — mcp-scanner runs in the sandbox.

**Platform items offered but not yet specced (each needs a spec first, per the session protocol):**
- Per-run target credentials — an ephemeral key in the run request, injected only as the env var the
  adapter already expects, never logged or placed on a command line. Unblocks testing targets that
  require an API key (today only no-key or any-key targets work). Spec-027 "out of scope" names this.
- A requests-per-minute limiter for garak (a pacing forwarder), so capped engagements can run garak
  instead of refusing it.
- Findings view grouped by probe family in the console.
- Digest-pinned adapter images (pin by sha256, not just tag).
- Auto staging deploy after merge.
- An operator guide.

**Further out (R2/R3 forecast):** ART adapter + model-artifact/dataset target types; supply-chain
(ModelAudit/ModelScan consensus + AI-BOM); guardrail-regression harness; IR/forensics trace import;
findings → detections; SSO/SCIM and multi-node adapter runners for production.

## 8. Open decisions owed to the owner

From `TASKS.md` and the Proposed ADRs — these block nothing in code but need a call:

- ADR-0006 — evidence-encryption key / KMS story and its **backup** (losing it loses all evidence).
- ADR-0016 (Proposed) — confirm the evidence envelope format and the ≥ 32-character key rule.
- ADR-0017 (Proposed) — campaign scheduling off Procrastinate (same least-privilege basis as 0015).
- Production CapRover server (Germany) confirmed (ADR-0010); backup location + first restore drill.
- Keycloak `khandaq` realm + `khandaq-api` client provisioned before the first real user.
- GitHub `staging`/`production` environments + secrets + `v*` tag ruleset for the promote workflow.
- Adapter-execution shape per server: docker-socket (staging/self-host) vs. dedicated runner host
  (production) — ADR-0009.
- Any pilot engagement runs **only** against systems with signed authorisation (SECURITY.md).

## 9. Working conventions (the short version)

- **One spec per session.** Read `CLAUDE.md`, `docs/architecture/03`, the scope/authz doc, and the
  one named spec. Present a plan, get approval, then implement. Don't start the next spec or refactor
  code the spec doesn't touch.
- `make lint` + `make test` before every commit. Semantic commits (`feat:`/`fix:`/`docs:`/
  `refactor:`/`chore:`/`test:`), scope = directory or adapter name, one logical change each.
- When a spec's acceptance criteria are met, tick them in the spec, mark it done in `TASKS.md`, and
  add one line per non-obvious decision.
- No secrets in code, config, fixtures or tests — env vars only; synthetic data only.
- Develop and push on `claude/kind-planck-xd0el7`. Don't open a PR unless asked.
</content>
</invoke>
