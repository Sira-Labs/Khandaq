# Spec 023 — Deployment status: what the API and its workers are configured with

Sprint 5, story S5-7. Depends on: 014, 016, 017, 021, 022. Packages: `api/` (deployment, worker,
migration 0011), `deploy/` (smoke test), `docs/`.

## Goal

After a redeploy, an operator cannot easily tell:
- whether the worker is alive;
- whether alerts are configured on it (they are worker settings);
- which mapping overlay or evidence store each process uses.

A dead worker leaves runs queued forever. A worker missing its alert settings drops alerts silently.

When this spec is done, `GET /api/deployment` (organisation admins only) shows the API's own
settings summary and each worker's summary, with its last heartbeat. No secret ever appears, only
whether each one is set. The smoke test fails when no worker has reported recently.

## User story

As the operator who just redeployed staging, I open one endpoint and see that the worker is
alive, has email alerts on, and uses the same mapping overlay as the API.

## Interface

- **Table (migration 0011).** `worker_heartbeats`:
  - `id`: `<hostname>:<pid>`, the primary key.
  - `started_at` and `seen_at`: timestamptz.
  - `app_version`: text.
  - `summary`: jsonb.
- **Summary** (`deployment.settings_summary`), the same shape for both roles:

  ```json
  {"role": "worker", "env": "prod",
   "evidence": {"key": true, "retired_keys": 1, "store": "s3", "bucket": "khandaq-evidence"},
   "alerts": {"webhook": true, "email": false},
   "campaign_min_interval_minutes": 60,
   "mappings": {"versions": {...}, "overlay": {"name": "...", "sha256": "sha256:..."} | null},
   "adapter_runtime": "docker-socket"}
  ```

  Only booleans and counts stand for secrets, URLs and addresses. The bucket name is included
  because it is not a secret and differs between deployments.
- **API.** `GET /api/deployment` returns
  `{checked_at, api: {app_version, schema_revision, summary}, workers: [{id, started_at, seen_at,
  alive, app_version, summary}]}`.
  - `alive` means the worker reported within the last 2 minutes.
  - `workers` lists heartbeats seen in the last 24 hours, newest first.
  - Organisation admins get 200, anyone else 403, and an unauthenticated caller 401.
- **Smoke test.** A new check, "a worker is alive", needs at least one `alive` worker. It runs
  only when the token belongs to an admin; otherwise it is reported as skipped, never as passed.

## Behaviour

1. **Heartbeat.**
   - The worker upserts its row when it starts and then at most every 30 s from its loop
     (`INSERT … ON CONFLICT (id) DO UPDATE`).
   - A database outage is retried like the rest of the loop.
   - At start, the worker deletes heartbeat rows not seen for 7 days, so restarts do not
     accumulate rows.
   - Heartbeats are operational telemetry. They change no engagement state, so they are not
     audited.
   - A failed heartbeat (any database error) is logged and retried after the interval. Telemetry
     never stops the worker from running work.
2. **No secrets.**
   - The summary is built only from booleans, counts, enum-like settings, the bucket name and the
     mapping table versions and overlay identity.
   - A test proves that every configured secret value (session secret, evidence keys, SMTP
     password, webhook secret and URL, alert recipients) is absent from the response.
3. **Authz.** The endpoint is organisation-wide, not per engagement, so only `org_role = admin`
   may read it. It reveals the deployment's shape, not its data.

## Acceptance criteria

- [x] A worker loop iteration writes its heartbeat; a second within 30 s does not; a row older
      than 7 days is pruned at start.
- [x] `GET /api/deployment` returns the API summary and the worker rows with `alive` computed from
      `seen_at`; admin 200, member 403 (no credentials: 401 in prod, through the shared
      authentication dependency).
- [x] No configured secret value appears anywhere in the response.
- [x] The smoke test passes with a live worker, fails with none, and reports "skipped" for a
      non-admin token.

## Test cases

Integration (`api/tests/test_deployment.py`, Postgres): heartbeat write, throttle and prune;
endpoint shape and `alive`; authz; secrets absent. Smoke (`test_smoke_script.py`): live worker,
no worker, non-admin skip.

## Out of scope

- Metrics and alerting on worker death (an external monitor can poll this endpoint).
- Showing this in the console (a later console spec).
