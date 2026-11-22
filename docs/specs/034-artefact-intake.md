# Spec 034 — Artefact intake for `model_artifact` and `dataset` targets

Sprint 8, story S8-3. Depends on: 002 (engagements, targets, scope), 014 (evidence store,
ADR-0016), 028 (the pattern for per-target data), 033 (the adapter this prepares for). Packages:
`api/src/khandaq/`, `api/tests/`, `web/src/api.ts`, `docs/`.

## Goal

A `model_artifact` or `dataset` target names its content by digest, and the scope lock matches it
by that digest. Until now Khandaq had no way to hold the content itself, so no tool could ever be
run on it. When this spec is done:

- An engagement owner uploads the bytes of such a target. Khandaq stores them only if their
  SHA-256 is the digest the target declares, encrypted at rest, write-once.
- The target's API view says whether its content is stored, and how large it is.
- The worker side has one function that returns the stored bytes, and only after they again match
  the digest.

Nothing runs on the content yet. Running ART on it is the next spec (see "Out of scope"); this
spec is split off because the intake is a control of its own: it is what guarantees that the bytes
a tool is later run on are the bytes the engagement authorised.

Khandaq never fetches an artefact from a `location`. An upload is the only way in, so the worker
opens no connection to a registry, a bucket or any other host on behalf of an artefact target.

## User story

As an assessor of a classifier I am authorised to test, I hand Khandaq the exact model file and
evaluation data that the statement of work names by digest, so that every later run is provably
on those bytes and on nothing else.

## Interface

- **Config** `KHANDAQ_ARTEFACT_MAX_MB` (default `64`, minimum `1`): the largest upload accepted.
  The content is held in memory once while it is hashed, encrypted and stored.
- **Table** `target_artefacts` (migration `0013_target_artefacts`): `id` (`tar_…`), `target_id`
  (unique), `engagement_id`, `sha256` (`sha256:<64 hex>`), `bytes`, `object_key`,
  `stored_by_user_id`, `created_at`. A composite foreign key pins the row to its target's own
  engagement, as for `target_credentials`.
- **Routes** (prefix `/api/engagements/{engagement_id}/targets/{target_id}`):
  - `PUT /artefact` — owner only. Body: the raw bytes (`application/octet-stream`). `201` with
    `ArtefactOut` when stored, `200` with the same when these bytes were already stored.
  - `GET /artefact` — any member. `ArtefactOut`, or `404` when nothing is stored.
  - No route returns the bytes, and none deletes them.
- **`ArtefactOut`**: `target_id`, `sha256`, `bytes`, `stored_at` (RFC 3339, UTC).
- **`TargetOut`** gains `has_artefact` (bool) and `artefact_bytes` (int or null).
- **Storage**: the evidence store (spec 014) under the object key
  `artefacts/<engagement_id>/<target_id>/<hex digest>`, as an ADR-0016 envelope under the evidence
  key. The key is bound to the engagement and the target, so a blob copied to another target's key
  does not decrypt.
- **Module** `khandaq.artefacts`: `store_artefact(session, target, content, *, actor, settings)`
  and `read_artefact(session, target, settings) -> bytes`.

## Behaviour

1. **Who and when.** Only the engagement `owner` (or an org admin) may upload. The engagement
   must be `draft` or `active`; a `closed` engagement answers `409`. The state is read under the
   engagement lock, so an upload cannot commit behind a concurrent close. The role is decided
   before the body is read and **again** before anything is stored: an owner who was demoted,
   disabled or (in production) taken off the allow-list while the body arrived gets `403`.
2. **Which targets.** The target must belong to the engagement (`404` otherwise) and be a
   `model_artifact` or a `dataset` (`409` otherwise). Its spec must carry a `digest` of the form
   `sha256:` followed by 64 lower-case hex characters (`409` otherwise): a target named only by
   `location` has nothing the bytes could be checked against, so it cannot hold content.
3. **Size.** A body larger than `KHANDAQ_ARTEFACT_MAX_MB` is refused with `413` as soon as the
   limit is passed; the rest is not read. An empty body is `422`. A body that has not arrived
   within ten minutes is `408`.
4. **The digest decides.** The SHA-256 of the body is computed by the API. If it is not the
   target's digest the upload is refused with `422`, nothing is stored, and the refusal is audited
   as `target.artefact_rejected` with both digests and the size. The client's own claim about the
   content (a header, a file name) is never read. Hashing, encrypting and the write to the
   store all happen before the engagement lock is taken, so neither a large or wrong upload nor
   a slow store makes evidence sealing or a close wait. Under the lock there is only the state
   check, the row and the audit entry.
5. **Stored once.** The bytes are encrypted and written write-once, then the row and the audit
   entry `target.artefact_stored` (target, type, digest, size) are committed together. Content
   exists for Khandaq only through its row: an object whose upload lost the race against a
   close, or whose commit failed, stays in the store without a row and is read by nothing. A repeat of the same upload finds the row and answers `200` without a second audit
   entry. An object left behind by an upload whose commit failed is accepted on the retry only if
   it is an envelope that decrypts to the same digest. The same bytes in plaintext at that key
   are not "already stored": `409`.
6. **Reading back.** `read_artefact` returns the plaintext only after it matches the row's digest
   **and** the digest the target declares now. A missing row, a missing object, an object that is
   not an envelope, a failed decryption or a mismatch raises `ArtefactError`; there is no partial
   result and no fallback. Unlike evidence from before spec 014, content is never read from an
   unencrypted object.
7. **Failures of the deployment.** No usable evidence key: `503`. The store is down or fails
   (an object-store error, a full or unwritable disk): `503`, also from `read_artefact`. In
   production with an empty `KHANDAQ_OBJECT_STORE_URL`: `503`, because the API would write into
   its own evidence directory, which the worker (another container) never sees. An object already
   at the content's key that is not this content: `409`, and it is not overwritten. In every case
   nothing is recorded as stored.
8. **Retention.** Stored content stays after the engagement closes, as its evidence does: the
   store has no delete, by design (ADR-0007). See the owner note in `TASKS.md`.
9. **Invariants.** The scope lock is unchanged and still decides every run: stored content gives
   no target any permission. `scope.py`, `audit.py`, the ledger and `evidence_store.py` are not
   modified. No audit entry, log line or error message contains artefact bytes.

## Acceptance criteria

- [x] An owner's upload whose SHA-256 equals the target's digest is stored encrypted, answers
      `201`, and is audited; the same upload again answers `200` and adds no audit entry.
- [x] A body with another digest is refused with `422`, stores nothing and is audited as rejected.
- [x] Operators, analysts, viewers and non-members cannot upload; any member can read the status.
- [x] Targets of another type, targets without a well-formed digest, closed engagements, empty
      and oversized bodies are refused with the status codes above, and nothing is stored.
- [x] `read_artefact` returns the bytes, and raises when the object was tampered with, moved from
      another target, or when no content is stored.
- [x] `TargetOut` shows `has_artefact` and `artefact_bytes`; no response contains content.
- [x] The stored object is an envelope: the plaintext does not appear in the store.

## Test cases

Integration (`api/tests/test_artefacts.py`, Postgres):
`test_an_owner_stores_content_that_matches_the_digest`,
`test_the_same_upload_twice_is_accepted_and_audited_once`,
`test_content_with_another_digest_is_refused_and_audited`,
`test_only_the_owner_uploads_and_every_member_reads_the_status`,
`test_targets_that_cannot_hold_content_are_refused` (other type, `location` only, malformed and
upper-case digests), `test_a_closed_engagement_refuses_an_upload`,
`test_empty_and_oversized_bodies_are_refused`, `test_target_reads_show_the_flag_and_the_size`,
`test_another_engagements_target_is_not_found`, `test_the_stored_object_is_encrypted`,
`test_read_artefact_returns_the_verified_bytes`,
`test_read_artefact_refuses_tampered_moved_and_missing_content`,
`test_an_object_left_by_a_failed_commit_is_accepted_on_retry`,
`test_an_object_that_is_not_the_content_blocks_the_upload`,
`test_the_right_bytes_in_plaintext_at_the_key_are_not_accepted_as_stored`,
`test_a_store_that_fails_is_a_503_and_records_nothing`,
`test_an_owner_who_lost_the_role_while_uploading_stores_nothing`,
`test_a_body_that_does_not_arrive_in_time_is_a_408`,
`test_a_wrong_upload_is_refused_without_waiting_for_the_engagement_lock`,
`test_no_evidence_key_is_a_503_and_stores_nothing`,
`test_production_without_an_object_store_refuses_uploads`,
`test_an_upload_cannot_slip_in_behind_a_concurrent_close`,
`test_a_slow_store_does_not_hold_the_engagement_lock`.
Integration (`api/tests/test_migrations.py`):
`test_0013_creates_the_artefact_table_an_upgraded_install_lacks`.
Unit (`api/tests/test_settings.py`): `test_the_artefact_size_limit_has_a_default_and_a_floor`.
Security: the digest, role, state and tamper tests above; every fixture is synthetic bytes.

## Out of scope

- **Running ART on stored content** (spec 035): a sandbox without any network, the hand-over of
  the model and the evaluation data into the container, which estimators are loaded and from which
  formats, how a run names its `dataset` next to its `model_artifact` and how the scope lock
  checks both, and registering the adapter.
- A console page for the upload (with spec 035, when there is something to run).
- Uploads larger than memory allows (multipart or streamed storage), if a pilot needs them.
- Deleting stored content (owner decision on retention, `TASKS.md`).
