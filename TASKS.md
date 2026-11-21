# Tasks — backlog and session notes

Backlog, spec status, and one line per non-obvious decision taken while implementing a spec. Specs live
in `docs/specs/`; the sprint plan is `docs/roadmap/sprints.md`.

## Legend
- [ ] todo · [~] in progress · [x] done

## R0 — design (this repository state)

- [x] Product page (`site/index.html`) + brand assets (`docs/assets/`)
- [x] Vision (`docs/VISION.md`) and architecture (`docs/architecture/01–04`)
- [x] Domain model incl. canonical finding; scope/authz/audit design; evidence-ledger design
- [x] Research synthesis (`docs/research/00–04`)
- [x] ADRs 0001–0012
- [x] Specs 001–007 (sprints 1–4)
- [x] Roadmap + sprint plan; CapRover deployment plan + compose/env/captain-definitions
- [x] Repo scaffold: README, CLAUDE.md, CONTRIBUTING, SECURITY, LICENSE, NOTICE, CI, templates, coderabbit

## R1 — the spine (specs to implement)

### Sprint 1 — foundation
- [x] S1-1 — spec 001 persistence schema + migrations + `/api/version` — all 12 tables, Alembic
      migration packaged in the wheel, entrypoint migrates on boot, 8 tests pass against Postgres.
      Decisions: append-only `audit_log` via a DB trigger (portable, single-role); `dedup_of` same-
      engagement via composite FK; enums as CHECKs; SQLAlchemy/psycopg pinned to 2.0.x / 3.2.x.
- [x] S1-2 — spec 002 engagements, scope lock, audit log (auth stubbed) — full lifecycle API,
      server-side scope lock (pure `scope.evaluate` + pre-flight route), append-only audit, per-
      engagement authz. 24 tests pass. Decisions: dev-auth stub refuses in prod (501) pending OIDC
      (spec 008); org admins act as owner; `run.rejected` audit lands with the run path (spec 005).
- [x] S1-3 — repo plumbing: `api/` uv skeleton (done, CI `api` job green), Dockerfiles for api + web,
      `release.yml` publishing images to GHCR (done); the `core/` cargo workspace (spec 003) and the
      `web/` pnpm app (spec 007) have since landed with their own CI jobs.
      Fix (2026-10-02): the khandaq-api image failed to build once `api/` gained the `khandaq-core`
      wheel dependency (spec 004) — the build context omitted `core/`, so `uv pip install .` could not
      resolve the `../core/khandaq-py` path source. The build stage now copies `core/` and a Rust
      toolchain (maturin builds the wheel; only the venv ships to the runtime stage); a root
      `.dockerignore` keeps `core/target` and other heavy trees out of the context.

### Sprint 2 — data spine
- [x] S2-1 — spec 003 canonical finding, fingerprint, dedup, severity, mapping (Rust core + wheel) —
      `core/` workspace (khandaq-core + khandaq-cli) + PyO3 wheel `khandaq_core`; 7 Rust tests + 5
      Python binding tests pass; clippy/fmt clean; CI `core` + `bindings` jobs online. Decisions:
      serde typed model mirrors finding.schema.json; fingerprint identity = mapping-ids+target+location
      (rule_id fallback); JSON-in/out bindings; `dedup_of` id-linking lands with spec 005.
- [x] S2-2 — spec 004 hash-chained evidence ledger — Rust `ledger` module (append/verify/root) + wheel
      bindings + API ledger service & read/verify endpoints; the api now depends on the `khandaq_core`
      wheel (api CI job gains a Rust toolchain). 5 Rust + 1 binding + 2 API ledger tests pass.
      **Follow-up:** Sigstore signing of the ledger root is deferred (offline chain works today).
- [x] S2-3 — spec 020 framework mapping tables applied at ingest: `builtin.json` is now schema
      `khandaq.mappings/1` with a version and a source per framework and an entry (with rationale)
      for every rule family the R1 adapters and `echo` emit, plus NIST AI RMF ids; keys are rule-id
      prefixes matched on a `.`/`:` boundary, longest first, a bare tool key being its default; the
      API stores the tool's ids plus the table's (`merge_mappings`), or `unmapped`; reports carry
      `mapping_tables`; `khandaq-core normalize` merges the same way. Decisions: the adapters keep
      their dicts (released images) and a drift test fails CI if one emits an id the core table
      lacks; garak has no default so an uncurated probe shows as `unmapped`; no stored finding is
      re-mapped (it is a record of what was reported); EU AI Act refs and a self-hoster overlay
      table are follow-ups.

### Sprint 3 — orchestration
- [x] S3-1 — spec 005 adapter contract + host + run execution — manifest model + CI validator; adapter
      registry + runners (in-process `echo`, `DockerRunner` command build); run service wires the scope
      lock onto the run path (rejected+audited), executes, seals evidence, normalises+dedups via the
      core, persists canonical findings; runs + findings-inbox endpoints. 33 api tests pass.
      **Follow-ups:** async execution on the Procrastinate worker (done in spec 012 on Khandaq's
      own worker, ADR-0015); evidence bytes upload to the object store (done, spec 014); real
      Docker execution lands with spec 006.
- [x] S3-3 — bundled vulnerable local target: partially covered by the in-process `echo` adapter for the
      demo/tests; a networked vulnerable target ships with the web demo (spec 007).
- [x] S3-2 — spec 006 garak adapter + contract test — `adapters/garak/` (Dockerfile pinned to
      garak 0.17.0, `wrap.py` report parser, `adapter.yaml`, Makefile); contract test parses a recorded
      garak fixture → 3 schema-valid, mapped findings; CI adapters job runs contract tests; release.yml
      publishes `khandaq-adapter-garak`. **Follow-up:** Docker execution + disk-manifest registry
      wiring (deploy-verified; needs a daemon).

### Sprint 4 — console + adapters + report
- [x] S4-1 — spec 007 web console — Vite + React 19 + TanStack Query + Tailwind v4 SPA (engagements
      list/create, engagement detail with scope-pre-flight run launcher + ledger status, findings inbox
      with severity filter + drawer). API read endpoints added (list engagements/targets/scope/members).
      web Dockerfile (multi-stage) + CI `web` job. 3 web tests (XSS-escaping, scope pre-flight) + 35 api
      tests pass. Bundled vulnerable target at `deploy/targets/vulnerable-llm/`. Deviations: minimal
      in-app router (TanStack Router later); echo launcher in-browser (garak via Docker in deploy);
      UI role-hiding deferred (enforced API-side).
- [x] S4-2 — spec 009 PyRIT adapter — `adapters/pyrit/` (Dockerfile pinned to pyrit 1.1.0, wrap.py
      parser for scored conversations, adapter.yaml, fixture, contract test); successful attacks →
      high findings. Adapter contract tests now run with `--import-mode=importlib`; release.yml
      publishes `khandaq-adapter-pyrit`. 5 adapter contract tests pass.
- [x] S4-3 — spec 010 promptfoo adapter — `adapters/promptfoo/` (Dockerfile pinned to promptfoo
      0.118.0, wrap.py parser for promptfoo JSON results, adapter.yaml, fixture, contract test); failed
      red-team tests → mapped findings by plugin family. release.yml publishes
      `khandaq-adapter-promptfoo`. 8 adapter contract tests pass.
- [x] S4-4 — spec 008 OIDC (Keycloak) BFF + real roles — auth package (`auth/oidc.py` injectable
      OIDC client, `auth/signing.py` HMAC login-state cookie, `auth/service.py` sessions + API
      tokens), `sessions` table (migration 0002), `routers/auth.py` (`/login` `/callback` `/logout`
      `/me` `/tokens`). `current_user` now resolves Bearer API token → session cookie → dev stub
      (non-prod); CSRF header enforced on session-authenticated mutations; prod fails closed without
      OIDC settings and no longer returns 501. 10 new tests (an injected fake IdP drives the full
      callback→session path) + test_settings; 48 api tests pass, ruff/mypy clean. Decisions:
      migration 0002 guards `CREATE TABLE sessions` on existence because 0001 is a `create_all`
      baseline that now also makes the table on a fresh DB; API tokens stored sha256-only, plaintext
      shown once; token-authenticated actions attributed via an audit contextvar (`actor_token_id`);
      live Keycloak end-to-end is deploy-verified (realm export at `deploy/keycloak/`).
- [x] S4-5 — spec 011 first report — `reports.py` builds a management summary (counts by severity +
      framework, evidence-ledger root + verify) and a technical finding list; endpoints `GET /report`
      (JSON), `/report.html` (escaped HTML), `/report/navigator` (ATLAS Navigator via the core). 38 api
      tests pass.

- [~] S4-6 — spec 012 adapter execution (closes R1: the exit criterion needs the tools to actually
      run). Part 1: `DockerRunner.run` builds a per-run `--internal` network whose only member
      besides the adapter is a stdlib TCP forwarder aliased as the target host and pinned to the
      address the worker resolved; loopback/link-local/multicast targets and IP literals are refused;
      the adapter I/O moved from host mounts to `KHANDAQ_RUN_REQUEST` + a stdout tar. A CI `e2e` job
      proves on a real daemon that the adapter reaches the target and not a decoy on the same
      network (with an uncontained control). Part 2: the API queues container runs (`run.queued` +
      `NOTIFY`); the worker claims with `SKIP LOCKED`, **re-checks the scope at claim time**, fails
      runs a lost worker left `running`, and retains evidence bytes write-once (hard-link, never
      overwrite) before sealing. The image gains the pinned static Docker CLI; compose gives the
      worker the socket's group, a fixed `khandaq` network and an evidence volume. Next: tools
      invoked by the adapters, mapping seeds.

- [x] S4-7 — spec 013 report re-verification: reports pin `{root, count}` from one chain read, JSON
      and HTML exports are audited as `report.exported` with that pin, `POST /report/verify` runs the
      core's `verify_pinned` and says whether this instance issued the pin, and
      `khandaq-core ledger-verify` checks an exported ledger offline (exit 0/1/2). 22 new api tests +
      5 CLI tests. Decisions: a broken pin is a 200 with `ok: false`, like `POST /ledger/verify`;
      `issued` is reported, not required (a pin read from `GET /ledger` has no export on record);
      reports exported before this spec have no `count` and get a 422, not a verdict; the
      GET export routes write the audit entry and commit before responding (doc 04 lists report
      export as audited; spec 011 had missed it); migration 0007 indexes `audit_log (engagement_id,
      action)` for the lookup; the count is a strict integer so `"3"` or `3.0` is refused, not
      coerced.

- [x] S4-8 — spec 014 evidence encrypted at rest + object store + download (ADR-0016, Proposed):
      every container-run evidence file is AES-256-GCM encrypted under its own data key, wrapped by a
      KEK derived (HKDF) from `KHANDAQ_EVIDENCE_KEY`, and stored write-once in the S3 store
      (`KHANDAQ_OBJECT_STORE_URL`, RustFS) or the local evidence dir; `GET …/evidence/{id}/content`
      (owner/operator/analyst) decrypts, checks the sealed sha256 and audits `evidence.downloaded`
      (409 + `evidence.integrity_failed` on mismatch). Decisions: the KEK is derived so every key
      shape already deployed (32 hex chars, base64) keeps working, but prod now refuses a key under
      32 characters; the AAD binds a blob to its object key; a retry is accepted only if the stored
      object decrypts to the same hash (ciphertexts differ by nonce); S3 writes HEAD first and then
      `If-None-Match: *`, so a store ignoring the condition still never overwrites; the worker
      creates a missing bucket with versioning; a run with bytes but no key fails before sealing;
      legacy plaintext files are served only if they match their seal. CI runs RustFS 1.0.0.
      **Owner:** ADR-0016 is Proposed — confirm the envelope format and the ≥ 32-character key rule.

- [x] S4-9 — spec 015 console catch-up: runs panel with state badges, duration and escaped failure
      reasons, polling every 5 s while a run is queued/running (and refreshing ledger + findings when
      one finishes); evidence download buttons in the finding drawer (403/404/409 explained); report
      JSON/HTML export as files and "verify a report" (drop an exported JSON). Decisions: downloads go
      through fetch + a revoked object URL so the dev header and CSRF behave like every other call,
      and nothing downloaded is rendered in the console's origin; the launcher stays `echo`.

### Sprint 5 — campaigns (R2)
- [x] S5-1 — spec 016 campaigns + diff (ADR-0017, Proposed): `campaigns` table (template, interval,
      `next_run_at`), `runs.campaign_id`, append-only `campaign_diffs`; the worker schedules due
      campaigns each loop (`SKIP LOCKED`) through the same `queue_run` the API uses (scope lock +
      audit), skips a window while the previous run is in flight, and never replays missed windows;
      a succeeded campaign run records new / regressed / resolved / unchanged against the campaign's
      earlier runs in the same transaction. Decisions: scheduling moved off Procrastinate (ADR-0017;
      same least-privilege objection as ADR-0015); a run's sightings include its linked duplicate
      rows, so "regressed" works across cross-run dedup; interval floor 60 min
      (`KHANDAQ_CAMPAIGN_MIN_INTERVAL_MINUTES`); the template is scope-checked at creation (refusal
      audited as `campaign.rejected`). Also: the worker now retries stale-run recovery while the
      database starts (PR #31 review). **Owner:** ADR-0017 is Proposed. Next: spec 017 alerts.
- [x] S5-2 — spec 017 alerts on a worsened campaign diff: an `alert_outbox` row is queued in the
      diff's transaction (migration 0009) when `KHANDAQ_ALERT_WEBHOOK_URL` is set; the worker POSTs
      it signed (`X-Khandaq-Signature` HMAC-SHA256), no redirects, under a `SKIP LOCKED` row lock,
      backing off 2^n minutes to `failed` after `KHANDAQ_ALERT_MAX_ATTEMPTS`; every outcome audited.
      Decisions: the webhook URL is deployment config, never per campaign (no operator-chosen
      exfiltration target); the payload carries rule ids, severities and counts only, never titles,
      evidence or target details; prod requires https + a 32-character secret. Email followed in
      spec 022 (S5-6).

- [x] S5-3 — spec 018 console campaigns: campaigns panel on the engagement page (list, create,
      enabled/paused), a campaign page with Pause/Resume, its runs (polling while in flight), its
      diffs (baseline / worsened / counts / escaped entries) and its alerts (hidden for viewers on
      403). Decision: the run list is shared with the engagement page (`RunList`); the form stays
      `echo`-only like the launcher until adapters run their tools.

- [x] S5-4 — spec 019 API tokens page + `deploy/smoke.py`: the console lists/creates (shown once)/
      revokes tokens; the stdlib-only script walks a deployment through 10 checks with a token,
      using the in-process echo adapter against `smoke.khandaq.invalid`, and closes what it
      creates. Running it found a real bug: an unreachable object store made evidence download a
      500 with a traceback; it is now a 503. Decision: the script's campaign starts in a day and is
      paused at once, so the smoke test never schedules a run.

- [x] S5-5 — spec 021 mapping overlay: `KHANDAQ_MAPPINGS_PATH` names a `khandaq.mappings/1` file
      the core combines with the built-in table (overlay keys replace or add; new frameworks
      allowed); the API and worker apply it at ingest, reports name it with its sha256, and
      `khandaq-core normalize --mappings` takes the same file. Decisions: an overlay may not
      change a built-in framework's version or source (two ATLAS releases in one report would be
      ambiguous); a broken overlay stops startup in every environment rather than falling back
      to the built-in table, which would quietly drop the deployment's own ids; 1 MiB limit; each
      finding records the table versions and overlay that mapped it (`x-khandaq.mapping_table`),
      and reports list those recorded tables, so a later restart under another overlay never
      changes what a report says produced its ids (PR #38 review).

- [x] S5-6 — spec 022 email alerts: `KHANDAQ_ALERT_EMAIL_TO`/`_FROM` + `KHANDAQ_SMTP_URL`/
      `_PASSWORD` add a plain-text email channel; migration 0010 gives `alert_outbox` a `channel`
      and makes `(diff_id, channel)` unique, so each channel is retried and audited on its own; the
      console's alert list shows the channel. Decisions: recipients are deployment config, never
      per campaign (same exfiltration argument as the webhook); each send runs under a hard 10 s
      deadline in a daemon thread, which makes email at-least-once (stable `Message-ID`); prod
      requires TLS (`smtps`/`smtp+starttls`) and refuses a password in the URL; CR/LF in names are
      flattened before they reach the subject; the 0010 downgrade refuses while email rows exist.

- [x] S5-7 — spec 023 deployment status: workers upsert a heartbeat (`worker_heartbeats`, migration
      0011) with a non-secret settings summary every 30 s; `GET /api/deployment` (org admins)
      shows the API's and each worker's summary with `alive`; the smoke test fails when no worker
      is alive (skipped, not passed, for a non-admin token). Decisions: secrets, URLs and
      addresses become booleans/counts in one function (`settings_summary`), with a test that no
      configured secret appears; a failed heartbeat is logged and never stops the worker; rows not
      seen for 7 days are pruned at worker start; heartbeats are telemetry, not audited.

- [x] S5-8 — spec 024 console deployment status: a **Deployment** page (admins; header link only
      for `org_role = admin`) shows the API card and the worker table from `/api/deployment`,
      refreshing every 30 s, with warnings when no worker is alive or a worker's mapping table
      (versions or overlay sha256) differs from the API's. Decision: a worker reporting no summary
      (older image) is not flagged as mismatched; a 403 shows "Organisation admins only."

### Sprint 6 — agentic & MCP (R2)

- [x] S6-1 — spec 025 Cisco mcp-scanner adapter — `adapters/mcp-scanner/` (Dockerfile pinned to
      `cisco-ai-mcp-scanner==4.8.5`, manifest, wrapper, recorded synthetic fixture, 40 contract
      tests); the release workflow publishes `khandaq-adapter-mcp-scanner`; the core table gains
      `mcp-scanner.prompt-injection`, `.data-exfiltration` and `.code-execution`, and the drift
      test covers the wrapper; negative scope tests pin exact-URL `mcp_server` and host+path
      `agent` matching. Decisions: one finding per item × analyzer × threat, with the threat name
      slugged (`PROMPT_INJECTION` and `PROMPT INJECTION` deduplicate); the raw format keeps one
      severity per analyzer entry, so its threats share it, and an entry left at `SAFE` with
      findings counted is `info` (the tool never promotes INFO); an errored analyzer entry is no
      finding, and a report where no item was scanned is refused; no `mcp-scanner` default
      mapping (uncurated threats stay `unmapped`, as for garak); the scope lock was not changed.

- [x] S6-3 — spec 026 console engagement setup: a draft engagement's owner adds targets (LLM
      endpoint, agent, MCP server by URL), saves a scope generated from them (optional requests per
      minute) and activates with the authorisation reference, all through the spec 002 routes; an
      active engagement shows its targets and locked scope read-only. The header shows "Signed in
      as" with email and role, and the primary sign-in button's label is legible again. Decisions:
      the scope is generated from the targets, not typed (deny, windows and techniques stay
      API-only); Activate stays off while the saved scope no longer matches the targets; the global
      link colour moved into Tailwind's base layer, because unlayered CSS beat the utilities.
- [x] S6-4 — spec 027 garak runs in the sandbox: the wrapper follows the spec 012 contract (request
      from the environment, garak 0.17.0 through `openai.OpenAICompatible`, report and hit log as
      evidence, tar on stdout, fail closed); `garak` is registered (drift-tested against
      `adapter.yaml`); `GET /api/adapters`; the run launcher offers the adapter and garak probe
      names; CapRover steps for an internal demo target or Ollama. Manual e2e on 2026-10-08: the
      real `DockerRunner` ran the image against the bundled vulnerable target, and the run
      succeeded with one high finding (`promptinject.HijackHateHumans`, 256/256), two sealed
      evidence files and a verifying ledger. Decisions: the base URI is the target URL minus
      `/chat/completions`, so garak's request path is the authorised URL; a new `paces_requests`
      manifest flag, and an engagement with an RoE rate cap refuses adapters that cannot pace (audited at
      creation and claim) rather than trust them; the parser accepts the one `digest` record garak
      0.17 writes after `completion` (found on the real run; the recorded fixture lacked it).
      Follow-ups: per-run target credentials; a pacing forwarder; PyRIT and promptfoo next.
      Fix after merge: the release now also tags each adapter image with its manifest's tag
      (`khandaq-adapter-garak:0.17.0` was never published) and publishes the demo target. The
      image installs the CPU build of `torch==2.14.0` before garak, because PyPI's default Linux
      torch is the CUDA build and no model runs in the container: 10.4 GB → 2.8 GB on disk
      (3.4 GB → 0.6 GB to pull); the manual e2e run was repeated with the new image.

### Sprint 7 — credentials, then the remaining adapters run (R2)

- [x] S7-1 — spec 028 per-run target credentials (ADR-0019; nightly run of 2026-11-14 under
      ADR-0018): one write-only secret per target, envelope-encrypted under a separate
      `KHANDAQ_CREDENTIAL_KEY` (off when unset); owner-only `PUT`/`DELETE …/targets/{id}/credential`,
      no read route, `has_credential` on targets, `credential_ref` nulled (migration 0012) and
      refused; the worker hands the key of the run's own target to an adapter that declares
      `accepts_credential` (garak) through the 0600 env file; `DockerRunner` redacts it from
      findings, evidence and errors before hashing; closing an engagement deletes its credentials;
      console key status and Set/Replace/Remove. 501 api tests, 135 adapter contract tests, 70 web
      tests. Manual e2e on 2026-11-14 (local daemon, garak 0.17.0, the bundled demo target started
      with `DEMO_REQUIRED_API_KEY`): no key stored → the target answers 401 and the run fails; key
      stored → the run succeeds with one high finding (`promptinject.HijackHateHumans`, 256/256),
      two sealed evidence files and a verifying ledger; a wrong key → failed run; the key was in no
      audit row, run row, finding, evidence object, report or log. Decisions: the five open points
      were taken at their stricter values (ADR-0019); `run.started` records `injected`/`none`/
      `not_accepted` at claim and execution loads the key only if it says `injected`, so a
      credential removed in between fails the run instead of running without it; redaction also
      covers a JSON-escaped solidus and happens before error text is cut; plain `ws`, IP literals
      and targets without a URL are refused like plain `http` to a dotted host; the `PUT` body is
      read untyped and `credential_ref` is refused in the route, because a validation error would
      echo the value; a failed run's recorded error now keeps its last lines (the 401 was cut off);
      the demo target gained the optional required key for the e2e. An independent review before
      merge (CodeRabbit was over its hourly limit) led to: credential changes and close take the
      engagement lock (a `PUT` could commit behind a concurrent close); redaction of
      percent-encoded unreserved characters and JSON `\u00XX` escapes; no credential for a target
      named by address; target-create validation moved into the route (the framework's 422 echoed
      a pasted `credential_ref`). `scope.py`, `audit.py` and the
      ledger are untouched.
      **Owner:** set `KHANDAQ_CREDENTIAL_KEY` (and keep it backed up) on staging api + worker to
      switch the feature on; it blocks testing hosted endpoints that need a key; default: stays off.
      **Owner:** ADR-0019 is Accepted by the implementer under ADR-0018 — say so if any of the five
      values should be looser; default: they stand.
- [ ] S7-2 — spec 029 PyRIT runs in the sandbox (to write, spec-027 pattern), and
- [ ] S7-3 — spec 030 promptfoo runs in the sandbox (to write). Both blocked.
      **Owner:** `docs/roadmap/handover.md` §6 records that writing these two invoke functions was
      stopped by a safety control of the coding assistant, and that it was not worked around.
      Nightly runs leave that control alone. Needed: a human writes the two wrappers (parser,
      manifest, Dockerfile, fixtures and tests exist; `adapters/garak/wrap.py` and
      `adapters/mcp-scanner/wrap.py` show the contract), or the block is cleared with the vendor.
      It blocks PyRIT and promptfoo runs only; default: they stay parser-only.
- [x] S7-4 — spec 031 mcp-scanner runs in the sandbox (second run of 2026-11-14, UTC): the wrapper follows
      the spec 012 contract (request from the environment, the scanner's own
      `mcp-scanner --analyzers yara --format raw remote --server-url <url>`, raw report as
      evidence, tar on stdout, fail closed); `mcp-scanner` is registered (drift-tested against
      `adapter.yaml`) with `paces_requests: false` and `accepts_credential: true`, so
      `GET /api/adapters` and the run launcher offer it. 505 api tests, 171 adapter contract
      tests. Manual e2e on 2026-11-14 (local daemon, the pinned 4.8.5 image, a local scratch MCP
      server with one benign and one deliberately poisoned tool description, all synthetic): the
      run succeeded with three high findings for the poisoned tool (prompt injection, data
      exfiltration, credential harvesting), the sealed raw report and a verifying ledger; against
      the same server requiring a bearer key the run failed without a stored key and succeeded
      with one (`run.started` `injected`), and the key was in no record. Decisions: the raw report
      is read from the scanner's stdout, because 4.8.5 ignores `--output` for a raw `remote` scan
      (found on the real tool); YARA is the only analyzer and any other request fails the run,
      because the others send tool descriptions to a third party; the credential is the
      scanner's `--bearer-token`, its only interface for one, so it is a process argument inside
      the run's container (never a `docker` argument); only `mcp_server` targets are scanned (the
      spec 025 `agent`-by-host case has no URL to scan); `MCP_SCANNER_*` and `VIRUSTOTAL_*`
      settings are stripped from the scanner's environment. A partial scan (an item failed, skipped, or with every analyzer errored)
      fails the run, stricter than the spec 025 parser (review). Known limit of the pinned tool:
      4.8.5 does not follow `tools/list` pagination, so on a paginating server only the first
      page is scanned and the report does not say so (review; spec 031). Follow-ups: a scanner
      version that paginates; a bundled demo MCP target
      for `make demo`; the scanner's prompts/resources/instructions scans (no raw report in
      4.8.5); refusing an adapter that does not fit the target type before the run is queued.

### Sprint 8 — pacing, then ART

- [~] S8-1 — spec 032 a pacing forwarder lets capped engagements run garak (nightly run of
      2026-11-16, UTC): implemented, tested and e2e-verified; the PR is open and **not merged**.
      The per-run egress forwarder takes `--pace-per-minute` and lets one *turn* through per
      `60 / rate` seconds (a turn: the first bytes a client sends on a connection, or after the
      target has answered), shared by all connections of the run. New manifest flag
      `forwarder_paced` (garak: true; mcp-scanner: false). `adapter_refusal` lets a capped
      engagement run a `forwarder_paced` adapter with a declared rate above 0; `run.started`
      records `paced_per_minute`. 577 api tests. Manual e2e on 2026-11-16 (pinned garak 0.17.0
      image, bundled demo target, all synthetic): 256 requests, closest two 100.1 ms apart at
      600/min against 3 ms unpaced. Decisions: the forwarder counts turns instead of requests,
      because it must not terminate TLS (ADR-0009), and over-counts rather than under-counts (a
      TLS handshake costs up to three turns); with pacing on it refuses a ClientHello that offers
      anything but `http/1.1` (or carries ECH, or cannot be parsed) and the HTTP/2 preface,
      because several requests in one turn would slip through; no burst, so a quiet spell earns
      nothing; while an engagement has a cap only one `forwarder_paced` run of it runs at a time
      (the next stays `queued`, checked under the engagement lock), because each forwarder holds
      only its own run's rate; a declared rate is paced without a cap too; an unusable rate
      refuses the run instead of falling back to an unpaced forwarder; `paces_requests` keeps its
      meaning and stays false for garak. Known limits (in the spec): pipelining inside TLS cannot
      be seen, so the flag is set per pinned tool version; very low rates can run into garak's
      request timeout. `scope.py`, `audit.py` and the ledger are untouched; the scope lock's
      rate rule decides first, as before. An independent review before the PR was left for the owner (CodeRabbit was
      over its hourly limit) led to: the target is connected to only at the slot; a request
      whose client gave up while waiting is dropped; a 30 s limit on a paced connection's
      opening; a run held back at the claim no longer reads as an empty queue. Follow-ups:
      pacing for mcp-scanner (its client holds event streams); a console hint that a capped
      garak run is paced and slower. CodeRabbit's review then led to: turns are let through one at
      a time and the interval counts from the real release, so late wakeups cannot bunch them;
      a run's first turn waits one interval after its forwarder started (the boundary to the
      previous run); a run whose containers cannot be removed, after the run or at recovery,
      stays `running` (audited as `run.cleanup_failed`) and keeps holding the next paced run
      back; removal is one object per call, and recovery now also runs every five minutes. A
      second CodeRabbit pass (2026-11-18): the turn is held while the target connection opens
      and until the first bytes are written, so a slow connect cannot bring two first requests
      closer (10 s connect limit while pacing); leftovers are looked for whatever the settings
      say now; a failed removal at recovery is audited once per run. A third pass (2026-11-21):
      a rate whose interval is infinite (`1e-308`) is refused at admission and by the forwarder,
      by one shared rule; an ALPN extension that names no protocol is refused; a request whose
      client left while the target connection opened is not sent; a run counts as lost only
      after the adapter timeout plus the limits of the runner's own steps (690 s: resolving the
      target now has a 30 s limit, then the Docker calls) plus ten minutes, so recovery cannot remove a live run's containers.
      **Owner:** review and merge the spec 032 PR. It changes how the rules of engagement's rate
      cap is enforced (a refusal becomes a paced run), so under ADR-0018 a nightly run does not
      merge it. It blocks garak on capped engagements; default: stays refused until merged.
- [x] S8-2 — spec 033 ART adapter (nightly run of 2026-11-18, UTC): `adapters/art/` wraps the
      Adversarial Robustness Toolbox 1.20.1 (MIT) with a parser for evasion-robustness results,
      a pinned image (published by the release run), a fixture recorded from a real ART run and
      45 contract tests; the core table maps `art.evasion` to ATLAS `AML.T0015`/`AML.T0043` and
      NIST AI RMF `MEASURE-2.7`, and the drift test covers the wrapper. Decisions: the sprint's
      story is split, as specs 009/010/025 were: this spec is the adapter, and running it in the
      sandbox is the next spec, because a `model_artifact` has no network endpoint and nothing
      yet brings an artefact and its evaluation data into the sandbox; so the adapter is not in
      the run registry and no run can be queued for it. ART writes no report of its own, so the
      wrapper defines the result line (ART's class, module, `attack_params`, estimator, and the
      numbers ART computed) and refuses results of another ART version. ART's own
      `compute_success` decides what a finding is, not the accuracy drop: on the recorded
      two-class run every prediction changed while accuracy only fell from 0.845 to 0.155,
      because flipping also "corrects" the samples the model had wrong. Severity uses garak's
      thresholds on that rate. Only the evasion family is read; privacy, extraction and
      poisoning results fail the run until each has its own meaning and mapping. No bare `art`
      default in the table. The image installs `packaging` by name: ART 1.20.1 imports it
      without declaring it (found on the real tool). The fixture is synthetic: a seeded
      scikit-learn classifier on `make_classification` data, FGSM twice, PGD and HopSkipJump.
      The scope lock already had `model_artifact` and `dataset`; it is untouched, as are the
      audit log and the ledger. Follow-ups: spec 034 ART in the sandbox (artefact and dataset
      intake with a digest check against the scope, estimator loading, registration); privacy
      and poisoning families; TextAttack and ML Privacy Meter.

### Dependency maintenance (nightly runs, ADR-0018)

- 2026-11-14: merged Dependabot #67 (serde_json 1.0.154), #73 (python-minor group: fastapi 0.162,
  sqlalchemy 2.1.6, alembic, boto3, pydantic-settings, pytest, ruff, mypy), #49 (docker/
  metadata-action 6), #52 (docker/setup-buildx-action 4). Grouped the five `web/` dev bumps
  (typescript 7, vitest 5, jsdom 30, jest-dom 7, plugin-react 5; Dependabot #53/#55/#57/#58/#59
  closed) into #75 with the `vite/client` declaration TypeScript 7 needs, and the three stale
  actions bumps (#47/#50/#51) into one PR. None of them had failed for a reason: nobody had merged
  them, and only #57 was red.
- 2026-11-14: psycopg 3.3.9 (range `<3.4`) and sha2 0.11.1 taken on one branch (Dependabot #56 and
  #69 closed). sha2 is the hash under the ledger and the fingerprint: the core's fixed-digest
  tests, the binding tests and the API's `hashlib` cross-checks pass, so no sealed hash changes.
- 2026-11-16: merged Dependabot #80 (docker/build-push-action 7), #81 (python-minor group) and
  #82 (npm-minor group); vite 8.3.8 and jsdom 31 taken on one branch (Dependabot #83 and #84
  closed; both rewrite the lockfile). No source change was needed for vite 8.
- [x] Python 3.15 base image for the api (Dependabot #72, 3.12-slim → 3.15-slim), 2026-11-18:
      taken on one branch with PyO3 0.26 → 0.30 (the `khandaq-core` wheel did not build on 3.15
      with 0.26; 0.30 needed no code change) and the CI jobs that test the api, the bindings and
      the e2e moved to 3.15, so CI tests what the image ships. `requires-python` stays `>=3.12`
      and the adapter images stay on their own pinned bases. Checked locally on 3.15: 505 api
      tests and the 13 binding tests pass. The image itself is first built by the release run.
      Built by release run #65. Follow-up from the review of #87: the api and bindings jobs
      also run on 3.12, the oldest version `requires-python` allows; the 3.15 jobs keep their
      names.
- [ ] **Owner:** Dependabot cannot label its PRs: the labels `dependencies`, `area: core`,
      `area: api`, `area: web`, `area: ci`, `area: deploy` named in `.github/dependabot.yml` do not
      exist. Create them, or say that they should be dropped from the file; default: unlabelled.

## Owner / external dependencies (not software; do not block sprints on these)

- [ ] Confirm the public name/domain: GitHub `Sira-Labs/Khandaq` is taken (good); check PyPI name and a
      domain if one is wanted.
- [ ] Production CapRover server (Germany) ordered/confirmed (ADR-0010).
- [ ] Keycloak `khandaq` realm + `khandaq-api` client (before the first real user). Staging: import
      `deploy/keycloak/khandaq-realm-staging.json` on `miftachun.apps.data-and-ai-dude.ch` (Create
      realm), then set the client/broker secrets and
      `KHANDAQ_OIDC_ISSUER=https://miftachun.apps.data-and-ai-dude.ch/realms/khandaq`.
- [ ] Evidence-encryption key / KMS story and its backup (ADR-0006); **losing it makes evidence unreadable**.
- [ ] Backup location for Postgres + evidence bucket; first timed restore drill (ADR-0010).
- [ ] GitHub environments (`staging`, `production`) + secrets + `v*` tag ruleset for promote.yml.
- [ ] Decide adapter-execution shape per server: A (docker socket) for staging/self-host, B (dedicated
      runner host) for production (ADR-0009).
- [ ] Any pilot engagement runs only against systems with signed authorisation (SECURITY.md).

## Decisions log (non-obvious choices)

- 2026-10-02 — R0 foundation laid: orchestrate-not-reimplement (ADR-0001) is the spine of everything;
  the scope lock, audit log and hash-chained evidence ledger are treated as the product, with CODEOWNERS
  and CodeRabbit path-instructions guarding them.
- 2026-10-02 — Canonical finding is a SARIF superset (ADR-0003) so results interoperate; dedup by stable
  fingerprint; severity normalised to five levels (ADR-0004); framework mappings are versioned data with
  both OWASP LLM 2025 and 2026 kept in parallel (ADR-0012).
- 2026-10-02 — Bootable control-plane image shipped so CapRover deploys stop failing at `khandaq-api`
  (no image existed at R0). `khandaq-api` boots with `/api/health` + `/api/version`, fail-closed in
  prod (settings.validate_runtime); `khandaq-web` serves the landing and proxies `/api`; both built and
  pushed to GHCR by `release.yml` on push to main. Domain features still land spec by spec.
- 2026-10-02 — Scope lock hardening (code review): on the old code 8 of 10 crafted targets/requests
  were allowed (e.g. `host` allowed while `base_url` pointed at a denied host; trailing-dot host
  dodging a `*.` deny; missing model under a model restriction; params overriding the model; an
  undeclared rate under a cap; a midnight window opening the previous night; a mistyped zone read as
  UTC) and a string rate crashed with a 500 and no audit record. Targets are now canonicalised and
  must be unambiguous; scope documents are validated on write; evaluation never raises. Spec 002 §6.
- 2026-10-02 — Full code review (4 parallel reviewers, findings verified before fixing). Auth: the
  realm brokers any Google/GitHub account and every login became an org `member` able to create
  engagements and start runs → sign-in now needs a verified email on `KHANDAQ_ALLOWED_EMAILS` (or
  `KHANDAQ_ADMIN_EMAIL`), mirroring Sahifa's `SAHIFA_ALLOWED_EMAILS`; `KHANDAQ_ENV` is strict
  (typos such as `production` would have enabled the dev stub); prod reads only the `__Host-` cookie;
  token attribution moved off a `ContextVar` that never crossed FastAPI's threadpool.
- 2026-10-02 — Adapters fail closed (code review, checked against the pinned upstream packages):
  garak 0.17 writes `total_evaluated`/`fails`, not `total`, so every real garak result was dropped
  and the run read as clean (the recorded fixture was hand-written in the wrong shape; re-recorded in
  the 0.17 shape). PyRIT is now read by `AttackResult.outcome`, with its string `score_value`
  ("0.9") understood; promptfoo errors (`failureReason` 2) are no longer findings. Each parser
  refuses a truncated, incomplete (no garak `completion` record, no wrapper completion count, stats
  mismatch), empty or all-errored report, and `main()` exits non-zero without writing
  `findings.jsonl`, so a run that produced nothing trustworthy fails instead of reporting zero
  findings. Invoking the tools inside the sandbox is still the spec 005/006 Docker follow-up.
- 2026-10-02 — Run-path integrity (code review): the run row and `run.started` were only flushed
  before the adapter executed, so a DB error while saving results (e.g. two concurrent runs racing
  for the same ledger `seq`) rolled back every trace of a run that had already reached the target.
  Now committed first, failures recorded in a fresh transaction, and appends serialised with a
  per-engagement advisory lock. Dedup now spans runs (partial unique index; `dedup_of` links);
  `evidence`/`ledger_entries` are append-only by trigger and TRUNCATE is blocked on all three.
  **Open decision for the owner:** the ledger seals only the adapter-reported sha256, so an evidence
  row's `object_key`/`run_id`/`kind` are outside the chain (triggers stop app-level edits, not a DBA).
  Binding a canonical evidence record into `evidence_hash` changes ADR-0007's formula and would
  invalidate existing staging chains — proposed, not done; needs an ADR. **Resolved by ADR-0014.**
- 2026-10-02 — Rust core hardening (code review): validation dropped every field the typed model
  did not name, which broke the SARIF superset, and it accepted `HIGH` and non-object locations,
  unlike the published schema. Both are fixed. Dedup is now independent of input order, keeps
  every tool's native severity (`x-khandaq.sources`) and unions `also_found_by`. The Navigator
  counts per finding. The ledger refuses malformed hashes and seq overflow, and gains
  `verify_pinned` to detect truncation. `khandaq-py` was outside the workspace, so CI never ran
  fmt/clippy/audit on it; the job now does. pyo3 is bumped from 0.22 to 0.26 (RUSTSEC-2025-0020;
  the affected API is unused here), which also clears pyo3 0.22's clippy false positive.
  **Open decision for the owner:** ADR-0013 (Proposed) would take framework mappings out of the
  fingerprint, because every mapping edit currently re-fingerprints the same issue and defeats
  cross-run dedup.
- 2026-10-02 — Staging naming + worker boot fix: staging is deployed as `khandaq-stg-<role>` on
  `https://khandaq-stg.siralabs.org` (the one-click's `<app>-<role>` shape); the docs said
  `khandaq-<role>-stg` and showed only production values. `deploy/caprover.md` now has a
  per-environment values table — the public origin must be identical on the web app's domain,
  `KHANDAQ_PUBLIC_URL` and the realm render, and the OIDC client id stays `khandaq-api`. Also fixed a
  spec-008 regression: `validate_runtime()` required OIDC settings for every prod role, so the
  worker (deployed without the client secret) would refuse to start; OIDC is now required for the
  `api` role only.
- 2026-10-02 — Keycloak realm import fix: the docs told operators to use **Partial import**, which
  skips `authenticationFlows`/`authenticatorConfig` and the `browserFlow`/`firstBrokerLoginFlow`
  bindings this realm relies on, so the realm came up broken ("could not be created"). Docs now say
  **Create realm → Resource file** (full import), matching Sahifa's working procedure. Also brought the
  realm in line with Sahifa (SSO cookie tried before the IdP redirect; `loginHint` on Google) and
  ported Sahifa's hardened `render.py`. The realm JSON was otherwise identical to Tabayyun's.
- 2026-10-02 — Real authentication landed (spec 008 / ADR-0005): OIDC Authorization-Code + PKCE
  against Keycloak, a backend-for-frontend `__Host-` session cookie (no tokens in the browser), CSRF
  on state-changing requests, and revocable, audited API tokens for automation. The dev header stub
  is now non-prod only; prod fails closed without OIDC and returns 401 (not 501) when unauthenticated.
  This completes the R1 spine: authenticated users → engagement → scope-locked run → deduped/mapped
  findings → sealed/verifiable evidence → framework-mapped report. All R1 specs (001–011) implemented.
- 2026-10-02 — Rust core (PyO3) owns the integrity-critical logic incl. the ledger (ADR-0011/0007);
  Python FastAPI control plane; Procrastinate on Postgres (ADR-0008); adapters isolated per container with
  egress limited to the in-scope target (ADR-0009).
- 2026-10-03 — Fingerprint v2 (ADR-0013 accepted by the owner): framework mappings are no longer
  identity. The fingerprint is `{v: 2, weakness, target, location}`, where `weakness` is the rule id
  unless a versioned equivalence table (`core/khandaq-core/mappings/equivalence.json`, shipped
  empty because no two R1 adapters share a location vocabulary) names a shared one. Schema id
  `khandaq.finding/2`; `/1` still validates. Migration `0004_fingerprint_v2` re-fingerprints stored
  findings, rebuilds `dedup_of`, recomputes a changed group's evidence from each member's own run
  (evidence rows carry `run_id`) and its tools from `source`/`sources`, carries triage over a merge,
  and audits `findings.refingerprinted` per engagement. Downgrade uses a Python copy of the v1
  recipe pinned against the old core's output. The echo adapter's duplicate pair now shares a rule.
- 2026-10-03 — Ledger seals evidence metadata (ADR-0014, owner decision): format-2 entries seal a
  canonical record of the evidence row (id, engagement, run, kind, object key, sha256, bytes,
  redacted) and tag the entry hash with `khandaq.ledger/2`. Without the tag, an entry could be
  relabelled format 1 with the record hash written into `evidence.sha256`, and any metadata would
  verify. Existing entries stay format 1 (migration 0005 adds the column without rewriting a row),
  so pinned report roots stay valid; formats may only rise along a chain; the 0005 downgrade is
  refused once format 2 is in use.
- 2026-10-03 — Users keyed by (`iss`, `sub`) (owner decision, spec 008 behaviour 9): keyed by email,
  a second IdP account that verified the same address became the first user and inherited their
  engagements. Migration 0006 adds `oidc_issuer`/`oidc_subject` (unique pair, both-or-neither) and
  changes no row; pre-0006 users are linked by email on their next verified sign-in. A known account
  follows a verified email change; an email linked to another account is refused, not merged.
  Recovery for a recreated Keycloak user (new `sub`) is a documented, deliberate unlink.
