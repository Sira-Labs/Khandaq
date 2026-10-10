# Spec 028 — per-run target credentials

Sprint 7, story S7-1. Depends on: 002 (scope lock, audit), 012 (adapter execution, env-file
injection), 014 (envelope encryption), 023 (deployment summary), 026 (console target form), 027
(garak in the sandbox). Implements ADR-0006 ("target credentials are encrypted at rest, referenced by
id, decrypted only at launch, injected as an ephemeral environment value for the single run, and
never written to logs, URLs, audit entries, findings or evidence"). Packages: `api/`, `adapters/garak/`,
`web/`, `deploy/`, `docs/`.

## Goal

Until now only endpoints that need no key, or accept any key, could be tested: garak runs with a
placeholder key (spec 027). Most real targets are hosted APIs behind a bearer key.

When this spec is done, an engagement owner stores **one secret per target**, for example the API
key of an in-scope LLM endpoint, encrypted at rest and write-only: nothing ever reads it back. When a
run starts, the worker decrypts it, hands it to the sandboxed adapter as a single environment
variable for that run, and the run ends with the key still absent from every record Khandaq keeps:
audit entries, run errors, findings, evidence, reports and logs.

The key travels exactly where the target's traffic already travels (the per-run forwarder to the one
in-scope host), so the scope lock and egress containment (spec 012) are untouched. "Per-run" means
the key is *injected* for one run and lives only in that run's container; it is stored per target so
that scheduled campaigns can use it too.

## User story

As an engagement owner, I add the API key for an in-scope endpoint once, in the console, and every
run and campaign against that target authenticates with it, without the key ever being shown again,
logged, or included in a report. I can replace it when it rotates and remove it when I am done.

## Interface

- **Config** (api and worker; the key must be identical on both):
  - `KHANDAQ_CREDENTIAL_KEY`: at least 32 characters. Unset means the feature is **off**: nothing
    else changes.
  - `KHANDAQ_CREDENTIAL_PREVIOUS_KEYS`: comma-separated retired keys that still decrypt, like
    `KHANDAQ_EVIDENCE_PREVIOUS_KEYS` (spec 014).
  - The key is **separate from `KHANDAQ_EVIDENCE_KEY`**, so that leaking or rotating one never exposes
    or breaks the other. Production refuses a placeholder, a key under 32 characters, a retired key
    under 32 characters, or a credential key equal to the evidence key.
- **Envelope**: `evidence_crypto.Keyring` unchanged (AES-256-GCM, DEK wrapped under an HKDF-derived
  KEK, spec 014), built from the credential key. The AAD object key is
  `credential/<engagement_id>/<target_id>/<version>`, so a blob moved to another target, engagement or
  version fails to decrypt. Losing the key loses only credentials, which an owner can enter again
  (unlike evidence).
- **Table `target_credentials`** (migration 0012): `id`, `target_id` (unique), `engagement_id` (must
  equal the target's; composite FK), `ciphertext` bytea, `version` int (starts at 1, +1 per change),
  `created_at`, `updated_at`, `set_by_user_id`. No plaintext column. The migration also sets the
  unused, free-text `targets.credential_ref` to `NULL` (it never held anything Khandaq read, and
  nothing stops someone having pasted a secret into it); the column stays, unused, until a later
  migration drops it.
- **API** (owner only; any member can read the flag):
  - `PUT /api/engagements/{id}/targets/{tid}/credential`, body `{"value": "<secret>"}`. Response
    `200 {"has_credential": true, "version": n, "updated_at": …}`. The response never contains the
    value.
  - `DELETE /api/engagements/{id}/targets/{tid}/credential`: `204`.
  - `TargetOut` gains `has_credential: bool` and `credential_updated_at: datetime | null`, and
    **loses `credential_ref`**. `TargetCreate` refuses a request that carries `credential_ref`
    (422, "send the key to the credential route"), so a secret pasted into the old field is rejected
    rather than silently kept or silently dropped.
  - There is no route that returns a stored value.
- **Value rules**: 8 to 1024 characters from `[A-Za-z0-9._~+/=:-]`. This covers bearer keys, JWTs
  and base64 secrets, and it is the set that survives a command line, an env file and JSON
  unchanged, which the redaction in Behaviour 7 relies on. Anything else is a 422 that names the rule
  and never echoes the value.
- **Manifest flag** `accepts_credential` (`AdapterManifest` and `adapter.yaml`, default `false`): the
  adapter consumes `KHANDAQ_TARGET_CREDENTIAL`. `garak` sets it; `echo` and the other adapters do not
  until their own specs. The drift test keeps manifest and `adapter.yaml` equal.
- **Runner**: `run(request)` is unchanged for adapters without a credential; with one, the worker calls
  `run(request, credential=<str>)`. `DockerRunner` writes it to the same 0600 env file as a second
  line, `KHANDAQ_TARGET_CREDENTIAL=<secret>`, never into the `KHANDAQ_RUN_REQUEST` JSON and never into
  any `docker` argument.
- **Adapter (garak)**: `KHANDAQ_TARGET_CREDENTIAL`, when present, becomes `OPENAICOMPATIBLE_API_KEY`
  for the garak process instead of the placeholder; it is never written to the generator option file,
  a report or stdout.
- **Audit actions**: `target.credential_set` (`{target_id, version, rotated}`),
  `target.credential_cleared` (`{target_id, reason}`), and `run.started` gains
  `credential: "injected" | "none" | "not_accepted"`.
- **Deployment summary** (spec 023): `credentials_enabled: bool`; the key itself never appears.
- **Console**: on each target row an owner sees "key set, updated <date>" or "no key", and a password
  field with **Set key / Replace key / Remove key**. Non-owners see only the status.
- **Docs**: `deploy/.env.example` and `deploy/caprover.md` gain the key (set on api and worker, how to
  generate one, how to rotate with the previous-keys list, what losing it costs).

## Behaviour

1. **Off by default.** With `KHANDAQ_CREDENTIAL_KEY` unset, `PUT` returns `503` ("target credentials
   are not enabled on this deployment"), no `target_credentials` row can exist, and runs are
   unchanged.
2. **Set or replace** (`PUT`). Owner only; any other role is `403`, a target outside the engagement is
   `404`. Allowed in `draft` and `active`, because a key rotates during an engagement and holding it
   changes no scope; a `closed` engagement is `409`. The value is validated (422), checked against
   Behaviour 3, encrypted, and stored in the same transaction as the audit entry, so a change never
   exists without its record. Replacing increments `version`; the old ciphertext is overwritten.
3. **No key over plain HTTP to a public-looking host.** The scheme comes from the same canonical
   endpoint the scope lock checks. A credential is refused (422) for a target whose URL is `http` and
   whose host contains a dot. `https` and single-label hosts (an internal service name such as
   `srv-captain--ollama`, which never leaves the deployment network) are allowed. The same check runs
   again just before injection, and a failure there fails the run.
4. **Clear** (`DELETE`). Owner only; `404` if none is set. The row is deleted outright, because
   destroying the secret is the point; `target.credential_cleared` records that it happened.
5. **Closing an engagement destroys its credentials.** In the same transaction as
   `engagement.closed`, every credential of that engagement is deleted, each with a
   `target.credential_cleared` (`reason: "engagement closed"`). A closed engagement holds no live
   secret.
6. **Injection.** The worker re-checks the scope at claim (spec 012, unchanged), then at execution it
   loads the credential of `run.target_id` only. If the adapter's manifest has `accepts_credential`,
   the key is decrypted and passed to the runner; if the target has a key and the adapter does not
   accept one, nothing is injected (`credential: "not_accepted"` in `run.started`, so the audit
   explains a 401); with no key the run is exactly as before (`"none"`). A stored key that cannot be
   decrypted (retired key removed, edited blob) **fails the run** with a message naming no secret.
   It never falls back to the placeholder. Campaign runs use the same path, so a scheduled run
   authenticates, and an expired key shows as a failed run.
7. **The key stays out of every record.**
   - The run request, which the runner and the adapter may log, never contains it.
   - After the adapter returns, `DockerRunner` replaces every occurrence of the key, raw and
     percent-encoded, with `[REDACTED:target-credential]` in findings and in every evidence file
     **before** the worker computes each file's hash. Evidence that changed gets `redacted: true`, so
     the ledger seals the redacted bytes and the unredacted ones are never stored. (A target that
     echoes its caller's key back is a finding in itself; the finding survives, the key does not.)
   - The tail of the adapter's stderr and any exception text are passed through the same replacement
     before they become `run.reject_reason` or an audit `error`.
   - Reports and exports are built from those records, so they cannot contain it. No log line carries
     it.
8. **Where the key can go.** It reaches the adapter container only, through the env file, which is
   removed in the `finally` as today. That container's only route is the forwarder to the one
   in-scope host (spec 012). The key of target A is never loaded for a run of target B.
9. **No existing behaviour changes without a key.** Targets with no credential, adapters that do not
   accept one, and deployments without the setting behave exactly as after spec 027.

## Acceptance criteria

- [ ] A key can be set, replaced and cleared by the owner only; the stored form is an ADR-0016
      envelope and no route, log line, audit detail or response ever contains the value.
- [ ] `KHANDAQ_CREDENTIAL_KEY` unset leaves everything unchanged and `PUT` is a 503; production refuses a
      placeholder, a short key, and a key equal to the evidence key.
- [ ] Value validation (length, character set) and the plain-HTTP rule are enforced at set time and
      again at injection.
- [ ] A garak run against a keyed target sends that key (and not the placeholder) as the generator's
      API key; the same run against an unkeyed target still sends the placeholder.
- [ ] The key appears in no `docker` argument, no `KHANDAQ_RUN_REQUEST`, no generator option file;
      it is in the env file only, and the file is gone afterwards.
- [ ] A target that echoes the key leaves it in no evidence file, finding, run error or audit entry;
      the evidence is marked `redacted` and its sealed hash matches the redacted bytes.
- [ ] Closing an engagement deletes its credentials, audited per target.
- [ ] `run.started` records `injected` / `none` / `not_accepted`; an undecryptable key fails the run.
- [ ] The console shows key status, sets, replaces and removes a key with a password field, and never
      renders, stores or caches the value.
- [ ] Manual e2e: garak against a target that requires a bearer key succeeds with the key set and
      fails (401, failed run) without it; the result is recorded in `TASKS.md`.
- [ ] Deployment docs cover the key, rotation, and the cost of losing it.

## Test cases

Unit (`api/tests/test_target_credentials.py`):
- `test_a_stored_credential_round_trips_and_is_bound_to_its_target_and_version`;
- `test_a_blob_moved_to_another_target_does_not_decrypt`;
- `test_value_rules_reject_bad_length_and_characters_without_echoing_the_value`;
- `test_plain_http_to_a_dotted_host_is_refused_and_an_internal_name_is_allowed`;
- `test_redaction_removes_raw_and_percent_encoded_forms`;
- `test_settings_refuse_a_placeholder_short_or_evidence_equal_credential_key`.

API / integration (`api/tests/`):
- `test_only_the_owner_can_set_replace_or_clear_a_credential` (operator, analyst, viewer and a member
  of another engagement are refused; a foreign target is a 404);
- `test_set_and_clear_are_audited_in_the_same_transaction_without_the_value`;
- `test_target_reads_show_the_flag_and_never_the_value`;
- `test_credential_ref_in_a_target_create_is_refused`;
- `test_a_closed_engagement_refuses_changes_and_closing_deletes_credentials`;
- `test_the_feature_is_a_503_when_the_key_is_unset_and_runs_are_unchanged`;
- `test_the_worker_injects_the_credential_of_the_runs_own_target_only`;
- `test_run_started_records_injected_none_or_not_accepted`;
- `test_an_undecryptable_credential_fails_the_run_and_never_falls_back_to_the_placeholder`;
- `test_a_campaign_run_uses_the_credential`;
- `test_the_deployment_summary_reports_enabled_without_the_key`;
- the manifest/`adapter.yaml` drift test covers `accepts_credential`.

Docker runner (`api/tests/test_docker_runner.py`, recording fake CLI):
- `test_the_credential_is_only_in_the_env_file_never_in_any_docker_argument`;
- `test_the_env_file_is_removed_even_when_the_run_fails`;
- `test_echoed_credentials_are_redacted_from_findings_and_evidence_before_hashing`;
- `test_stderr_and_error_text_are_redacted_before_they_are_recorded`.

Adapter contract (`adapters/garak/tests/test_contract.py`):
- `test_the_credential_becomes_the_generator_api_key_and_the_placeholder_is_the_fallback`;
- `test_the_credential_is_in_no_command_argument_option_file_or_output`.

Web (`web/src/__tests__/engagement.test.tsx`):
- owner sets, replaces and removes a key through a password field; the field is cleared after
  submit; the value is absent from the rendered page, the query cache and storage;
- non-owners see the status only.

Security (the invariants):
- a run for target B never receives target A's key;
- a secret sweep: after a full keyed run, the key is not in any audit row, run row, finding, evidence
  object, report export, or captured log of the test.

## Out of scope

- Other adapters consuming the key (PyRIT, promptfoo, mcp-scanner): each adds `accepts_credential`
  and its own mapping in its own spec (029 onwards). Only garak consumes it here.
- More than one secret per target, custom header names, Basic auth, or OAuth/token-exchange flows:
  a later spec if a real target needs them.
- An external secrets manager or KMS in place of the environment key: ADR-0006 keeps it optional;
  it is a later spec.
- Encoded forms of the key beyond raw and percent-encoded (for example base64 inside a Basic header)
  in the redaction.
- A reminder or alert for a key that is old or rejected by the target.
- Dropping the unused `targets.credential_ref` column.
