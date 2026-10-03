# Spec 019 — API tokens in the console, and a deployment smoke test

Sprint 5, story S5-4. Depends on: 008, 013–018. Packages: `web/`, `deploy/`, `api/` (one fix).

## Goal

An operator can check a deployment end to end with one command. They create an API token in the
console, run `deploy/smoke.py` against the deployment, and get one line per check of the spine. The
script uses only the in-process `echo` adapter against a reserved, unresolvable host, so nothing
leaves the API process. It closes what it creates.

## User story

As the owner, after a deploy to staging, I run one script and know that sign-in, the scope lock,
runs, the ledger, reports, evidence, campaigns and alerts all work, without clicking through the
console.

## Interface

- **Console** `/tokens` (header link "API tokens"): your tokens (name, created, last used,
  revoked), **Create token** (the plaintext is shown once, with a warning), **Revoke**. Uses the
  existing `GET/POST /api/auth/tokens` and `DELETE /api/auth/tokens/{id}`.
- **Script** `deploy/smoke.py --url <public URL> [--token …]` (or `KHANDAQ_TOKEN`). Python 3.10+,
  standard library only. Exit 0 when every check passes, 1 on the first failure (after closing the
  engagement it created), 2 without a token.
- **Checks:**
  1. Health, and a numeric schema revision of at least `0009`.
  2. The token authenticates (`/auth/me` says `token`).
  3. Engagement created, targeted (`smoke.khandaq.invalid`), scoped and activated.
  4. Scope pre-check allows the in-scope target, and a run whose params override the model is
     `rejected`.
  5. An echo run succeeds with 2 deduplicated findings.
  6. The ledger verifies.
  7. The report exports (JSON, HTML) and re-verifies against its pin, marked issued.
  8. The evidence route answers (404: echo evidence has no stored bytes).
  9. A campaign is created (starts in a day, every 24 h) and paused; diffs and alerts are readable.
  10. The engagement closes and its report still verifies.
- **API fix** found by the script: an evidence download while the object store is unreachable
  answered 500 with a traceback. It now answers `503 "evidence store unavailable; try again later"`
  and logs the store's error code.

## Acceptance criteria

- [x] The tokens page lists, creates (shown once) and revokes tokens; a refusal shows its message.
- [x] `deploy/smoke.py` passes 10/10 against the app (pytest via the test client with a real API
      token) and over real HTTP against a local API with RustFS.
- [x] A failing check prints `✗`, closes the engagement it created and exits 1; an unmigrated API
      (`schema_revision: none`) fails check 1; no token exits 2.
- [x] An unreachable evidence store gives 503, not 500.

## Test cases

`api/tests/test_smoke_script.py` (pass, failure + cleanup, unmigrated API, no token);
`api/tests/test_worker.py::test_an_unreachable_evidence_store_is_a_503_not_a_crash`;
`web/src/__tests__/tokens.test.tsx`.

## Out of scope

- Token scopes or expiry (tokens carry the user's roles until revoked; R3 API-token hardening).
- A smoke test that drives container adapters (needs spec 012 part 3).
