# Spec 032 — A pacing forwarder lets capped engagements run garak

Sprint 8, story S8-1. Depends on: 002 (scope lock, `roe.max_requests_per_minute`), 012 (adapter
execution, egress forwarder), 027 (garak in the sandbox, `paces_requests`). Packages: `api/`,
`adapters/garak/`, `web/`, `docs/`.

## Goal

Since spec 027 an engagement whose rules of engagement cap the request rate refuses garak: garak
has no limiter, and an adapter that cannot hold a rate is not trusted to stay under one. Real
engagements usually carry a cap, so garak is unusable exactly where it is needed.

When this spec is done, the per-run egress forwarder (spec 012) holds the rate for garak. It is the
only way out of the sandbox, it is started by the worker, and it lets one request through per
`60 / rate_per_minute` seconds. A capped engagement can run garak; the run's `run.started` audit
entry records the rate it was held to. Nothing changes for an engagement without a cap, and
nothing changes for mcp-scanner, which stays refused under a cap.

The forwarder still relays to exactly one checked address and still passes TLS through untouched.
It adds a delay; it adds no destination.

## User story

As an operator on an engagement whose customer allows 60 requests per minute, I start a garak run
with `rate_per_minute: 60` and the run goes through, slower, without exceeding what was agreed.

## Interface

- **Forwarder** (`api/src/khandaq/egress_forwarder.py`): new optional flag
  `--pace-per-minute <number>` (finite, greater than 0). Without it the forwarder behaves exactly
  as before.
- **Manifest flag** `forwarder_paced` (`AdapterManifest` and `adapter.yaml`, default `false`): the
  adapter talks to its target in plain request/response HTTP/1.1 (no HTTP/2, no pipelining, no
  protocol upgrade), so the forwarder's pacing holds a requests-per-minute limit for it.
  - garak sets it. mcp-scanner does not (see "Out of scope"). `paces_requests` keeps its meaning
    (the adapter holds the rate itself) and stays `false` for garak.
- **API**: `GET /api/adapters` adds `forwarder_paced` to each entry.
- **Audit**: `run.started` gains `paced_per_minute` (the number the forwarder is started with) for
  a paced run; the key is absent otherwise. New action `run.cleanup_failed` (`run_id`, `error`):
  a run's containers could not be removed and the run stays `running`.
- **Runner**: `DockerRunner` starts the forwarder with `--pace-per-minute <rate>` when the manifest
  is `forwarder_paced` and the run's params declare `rate_per_minute`.
- No new setting, no migration.

## Behaviour

1. **What counts as a request.** The forwarder cannot read TLS, so it counts *turns*. A turn starts
   with the first bytes a client sends on a connection, and again with the first bytes it sends
   after the target has sent anything on that connection. In HTTP/1.1 without pipelining a client
   sends a request only at the start of a connection or after the previous response, so every
   request starts a turn. A turn that is not a request (the parts of a TLS handshake, a request
   body continued after an early response) is counted too: the count is never below the number of
   requests.
2. **Pacing.** The forwarder holds the first bytes of a turn until the turn's slot. Turns are let
   through one at a time, at least `60 / rate` seconds after the one before, shared by all
   connections of the run, with no burst: in any 60-second window that starts at a turn, at most
   `rate` turns (rounded up) are let through. The distance counts from when a turn was really let
   through, so wakeups that come late and together cannot bunch turns. The first turn of a run
   is not let through before one interval after the forwarder started, which keeps the distance
   to the last request of the engagement's previous run.
   Bytes within a turn and everything the target sends are relayed without delay.
   - The forwarder connects to the target only when a connection's first slot has come, so the
     target sees nothing of a waiting connection, not even a TCP handshake.
   - A client that closes while its turn waits (a timeout, then a retry) has that request
     dropped: the slot is used up, but the target is not sent a request nobody waits for.
3. **Tripwires, fail closed.** Pacing by turns is only sound for HTTP/1.1. With pacing on, the
   forwarder closes a connection before relaying a byte when:
   - a TLS ClientHello offers any ALPN protocol other than `http/1.1`, carries an Encrypted Client
     Hello extension, spans more than one TLS record, or cannot be parsed;
   - a plaintext connection opens with the HTTP/2 preface;
   - a connection does not show its opening bytes within 30 seconds.

   The adapter then sees a connection error and the run fails (spec 027 §2). A client that offers
   no ALPN at all cannot negotiate HTTP/2 and is relayed.
4. **Which runs are paced.** A run is paced when its adapter is `forwarder_paced` and its params
   declare `rate_per_minute`, whether or not the engagement has a cap: a declared rate is kept.
   The scope lock (spec 002) is unchanged: with a cap it still requires a declared rate at or
   under the cap.
5. **The adapter check** (spec 027 §3) becomes: with a cap in the rules of engagement,
   - an adapter with `paces_requests` passes, as before;
   - an adapter with `forwarder_paced` passes when the declared rate is a number greater than 0;
   - any other adapter is refused, as before.

   A `forwarder_paced` adapter with a declared rate the forwarder cannot hold (0, or not a finite
   number) is refused with or without a cap ("a rate of 0/min lets the run send nothing"): the run
   could only time out.

   It applies at the same places: run creation, the campaign scheduler, the worker's claim,
   campaign creation and the pre-flight.
6. **One paced run per engagement at a time.** The cap belongs to the engagement, a forwarder to
   one run. Two paced runs side by side would each keep their own rate and together exceed the
   cap. So while an engagement has a cap, the worker starts a `forwarder_paced` run only when no
   other `forwarder_paced` run of that engagement is `running`; the later one stays `queued`
   (it is not rejected) and is taken once the first has ended. The check is made under the
   engagement lock, so two workers cannot both start one. Other engagements, runs without a cap
   and built-in adapters are not held back.
7. **A run is not over while its containers are there.** Each forwarder holds only its own run's
   rate, so a forwarder left behind could relay beside the next paced run.
   - After every container run the runner removes the adapter, the forwarder and the network, one
     object per call (an object already gone counts as removed). If one cannot be removed the
     run is **not** recorded as ended, whatever its own outcome: it stays `running`, its result
     is dropped, and `run.cleanup_failed` is audited.
   - `recover_stale_runs` does the same removal for a run left `running` past the timeout (a lost
     worker, or the case above) and only then records `run.failed`; if the removal fails the run
     stays `running`. The worker runs this at start and every five minutes.
8. **A paced run that cannot be paced fails.** If the runner is asked to pace with a rate that is
   not a finite number above 0, it raises before any container starts; nothing falls back to an
   unpaced forwarder.
9. **Invariants.** The forwarder's destination is still the one address the worker resolved and
   checked; pacing adds no way to reach anything else. No run that the scope lock refuses is
   allowed by this spec. Every paced start is in the audit log with its rate.

## Limits, stated plainly

- The guarantee rests on the adapter speaking HTTP/1.1 without pipelining or a protocol upgrade.
  The ALPN and preface tripwires catch a tool that starts to offer HTTP/2; pipelining inside TLS
  cannot be seen by anyone but the endpoints. `forwarder_paced` is therefore set per adapter,
  for a pinned tool version, and reviewed when the pin moves. garak 0.17.0 uses the `openai`
  client over `httpx` with HTTP/2 off, which offers only `http/1.1` and does not pipeline.
- A TLS connection costs up to three turns for its handshake, so the real request rate is slightly
  below the declared one.
- The client waits for its slot inside its own request timeout. At very low rates (a few per
  minute) garak may time out and retry; each retry is paced too, so the cap holds, but the run can
  hit `KHANDAQ_ADAPTER_TIMEOUT_SECONDS` and fail.

- One paced run at a time relies on the run's recorded state. A worker that dies mid-run leaves
  its containers behind, so recovery at the next worker start removes the lost run's containers
  and network before it marks the run failed, and leaves it `running` (still holding the next
  paced run back) when that removal fails. Until a worker starts again the lost run stays
  `running` and nothing paced starts beside it.
- A cap that is added or lowered while a run is running does not slow that run (true of every
  rule of engagement since spec 002: they are checked at creation and at the claim).
- The tripwires look at a connection's opening only; a later protocol upgrade is not seen.

## Acceptance criteria

- [x] `--pace-per-minute` spaces turns `60 / rate` seconds apart across all connections; without
      the flag the forwarder relays as before.
- [x] With pacing on, a ClientHello offering `h2`, one with ECH, an unparsable one and the HTTP/2
      preface are closed without a byte reaching the target; an `http/1.1`-only ClientHello and a
      plaintext HTTP/1.1 request pass.
- [x] garak's manifest and `adapter.yaml` set `forwarder_paced`; the drift test covers the flag;
      `GET /api/adapters` returns it.
- [x] A capped engagement accepts a garak run with a declared rate above 0 at creation, at the
      claim, for a campaign and in the pre-flight; rate 0 and mcp-scanner are still refused.
- [x] `run.started` records `paced_per_minute` for a paced run and not otherwise.
- [x] The runner passes `--pace-per-minute` exactly for paced runs and raises on an unusable rate.
- [x] A second paced run of a capped engagement stays queued while the first is running and is
      claimed afterwards; a run of another engagement is claimed meanwhile.
- [x] A real garak 0.17.0 run against the bundled demo target under a cap succeeds and the target
      sees no two requests closer than the pace allows.

## Test cases

Unit (`api/tests/test_egress_forwarder.py`): `test_pacer_spaces_turns`, `test_pacer_shares_slots`,
`test_pacer_keeps_the_interval_after_a_stall`, `test_pacer_wakes_early_and_still_waits_out_the_slot`,
`test_the_first_turn_waits_for_the_first_slot`,
`test_pace_argument_must_be_positive`, `test_paced_relay_counts_one_turn_per_request`,
`test_unpaced_relay_is_unchanged`, `test_client_hello_alpn`,
`test_client_hello_that_cannot_be_judged_is_refused`, `test_paced_relay_refuses_h2_client_hello`,
`test_paced_relay_refuses_h2_preface`, `test_paced_relay_passes_an_http11_client_hello`,
`test_paced_forwarder_holds_the_rate_end_to_end` (the real process, from its source alone),
`test_the_target_sees_nothing_of_a_connection_before_its_slot`,
`test_a_request_abandoned_while_waiting_is_not_delivered`,
`test_a_paced_connection_that_never_shows_its_opening_is_dropped`.
Unit (`api/tests/test_docker_runner.py`): `test_forwarder_is_paced_for_a_paced_adapter`,
`test_forwarder_is_not_paced_without_a_rate_or_flag`, `test_unusable_pace_refuses_the_run`,
`test_leftovers_of_a_lost_run_are_removed`, `test_leftovers_that_are_already_gone_count_as_removed`,
`test_leftovers_that_cannot_be_removed_are_reported` (with the mixed cases),
`test_a_run_whose_containers_cannot_be_removed_ends_in_leftovers` (timeout, failure, success),
`test_a_failed_removal_is_reported_as_leftovers_and_its_logs_are_redacted`.
Integration (`api/tests/test_worker.py`):
`test_a_lost_run_whose_containers_cannot_be_removed_stays_running`,
`test_a_run_that_leaves_containers_behind_stays_running_and_is_audited`.
Unit and integration (`api/tests/test_adapter_registry.py`): `test_adapter_refusal_for_a_rate_cap`
(the table), `test_only_garak_is_paced_by_the_forwarder`,
`test_a_capped_engagement_runs_garak_paced_and_audits_the_rate` (pre-flight, campaign, create,
claim, audit), `test_an_unpaced_run_records_no_pace`,
`test_paced_runs_of_a_capped_engagement_run_one_at_a_time`,
`test_two_workers_cannot_both_start_a_paced_run` (the recheck),
`test_the_engagement_lock_makes_a_second_worker_wait_for_the_first` (two sessions, real lock), `test_uncapped_paced_runs_are_not_held_back`;
the spec 027 refusal tests now use mcp-scanner, which is still refused.
Security: `test_the_scope_lock_still_decides_before_pacing` (no rate, a rate above the cap and a
zero rate are still rejected and audited for garak); the scope lock's own tests are untouched.

## Verified on the real tool

Manual e2e on 2026-11-16 (local daemon, the pinned garak 0.17.0 image, the bundled demo target,
all synthetic; a scratch recorder in front of the target noted when each request arrived):

- without a cap and without a rate: 256 requests in about 18 s, the closest two 3 ms apart;
- cap 600/min, rate 600/min: the same 256 requests, the closest two 100.1 ms apart (the
  slot is 100 ms; before the interval counted from the real release, earlier runs measured 97
  to 99 ms), run succeeded, same finding, ledger
  verifies, `run.started` has `paced_per_minute: 600`.

The ClientHello that the image's `openai` 2.54.0 / `httpx` 0.28.1 client sends was captured and
read with the forwarder's own parser: it offers `http/1.1` only.

## Out of scope

- Pacing mcp-scanner: its MCP client holds long-lived event streams; whether turn counting is
  sound for it needs its own look (backlog).
- A cap shared with runs that hold the rate themselves (`paces_requests`): only `echo` does today,
  and it sends nothing.
- Counting requests exactly by terminating TLS at the forwarder: rejected, it would end
  end-to-end certificate checks (ADR-0009).
- PyRIT and promptfoo (specs 029, 030, blocked for the owner).
