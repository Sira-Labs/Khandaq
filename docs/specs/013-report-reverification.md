# Spec 013 — Report re-verification against the pinned ledger root

Sprint 4, story S4-7. Depends on: 004, 008, 011. Packages: `api/` (reports, ledger), `core/`
(`khandaq-cli`).

## Goal

A report already pins the evidence-ledger root (spec 011), but nothing checks that pin afterwards. Plain
`verify` cannot notice entries removed from the end of a chain, and a root alone does not say how many
entries it covered. When this spec is done, a report pins `{root, count}`, every export is audited with
the pin it issued, and anyone holding an exported report can ask the instance, or check offline with
the `khandaq-core` CLI, whether the evidence it relies on is still intact and unchanged. The check uses the
core's `verify_pinned` (spec 004 follow-up).

## User story

As a compliance/governance lead, I re-verify a report I received weeks ago so that I know its evidence
was not altered, truncated or replaced since it was issued.

## Interface

- `GET /api/engagements/{id}/report` (spec 011): the `evidence` block becomes
  `{root, count, verify}`. `count` is the number of ledger entries `root` covers (`0` and `root: null`
  for an empty chain). `report.html` shows the count next to the root.
- `POST /api/engagements/{id}/report/verify` (any member). Request:
  `{"root": "sha256:<64 hex>" | null, "count": <int ≥ 0>}`. Extra keys are ignored, so the exported
  report's `evidence` block can be posted as is. Response 200:

  ```json
  {
    "ok": true,
    "pinned":  {"root": "sha256:…", "count": 3},
    "current": {"root": "sha256:…", "count": 5},
    "appended_since": 2,
    "issued": true,
    "verify": {"ok": true, "count": 5}
  }
  ```

  `verify` is the core `VerifyResult` (`{ok, count, broken_at?, reason?}`) of `verify_pinned`, or of
  `verify` for an empty pin.
  `appended_since` is `current.count - pinned.count` when `ok`, else `null`. `issued` says whether this
  instance's audit log holds a `report.exported` entry for this engagement with exactly this pin.
- `GET /api/engagements/{id}/ledger` (spec 004) also returns `count`, the number of entries.
- Audit action `report.exported`, detail `{format: "json" | "html", root, count}`, written by
  `GET /report` and `GET /report.html`. The Navigator layer pins nothing and is not audited.
  Migration `0007_audit_log_engagement_action` indexes `audit_log (engagement_id, action)` for the
  `issued` lookup; it changes no row.
- CLI: `khandaq-core ledger-verify <file> [--root <hash> --count <n>]`. `<file>` is the JSON of
  `GET /ledger` (or just its `entries` array). It prints the `VerifyResult` and exits 0 when intact,
  1 when broken, 2 on unreadable input or `--root` without `--count` (and the reverse).

## Behaviour

1. Building a report reads the chain once (`ledger.chain_status`) and pins its root and entry count
   together, so the pin never mixes two reads.
2. `GET /report` and `GET /report.html` record `report.exported` with the pinned root and count in the
   same transaction and commit it before responding. A failed audit write fails the export (500): a
   report this instance issued is always on record.
3. `POST /report/verify` validates the body: `root` must match `^sha256:[0-9a-f]{64}$` or be `null`;
   `count` is an integer between 0 and 2⁶³−1; `root` is `null` exactly when `count` is 0. Any other
   body → 422, and nothing is read.
4. It loads the chain in one read. For `count ≥ 1` it runs `verify_pinned(entries, root, count)`; for
   the empty pin it runs `verify(entries)` (every chain extends the empty one). A broken chain, a chain
   shorter than the pin (entries removed) or an entry at `count` whose hash is not the pinned root
   gives `ok: false` with the core's `broken_at` and `reason`. It is still a 200: the answer is the
   verification result, the same as `POST /ledger/verify`.
5. `issued` is looked up in `audit_log` (`action = 'report.exported'`, this engagement, matching root
   and count). It is information, not a condition of `ok`: a report from before this spec has no audit
   entry yet can verify. A client must treat `ok: true, issued: false` as "the evidence is intact,
   but this instance has no record of issuing this pin".
6. Re-verification only reads; it writes no audit entry and changes no engagement state. It works in
   every engagement state, `closed` included (doc 04: reports remain verifiable).
7. Authorisation follows the other report routes (`require_engagement_role()`): any engagement member
   may verify; a non-member gets 403, an unknown engagement 404, an unauthenticated caller 401.
8. The CLI runs the same core functions offline, without trusting the instance's verdict. It checks
   that the exported entries chain together and reach the pinned root; it cannot recompute the
   `evidence_hash` of each entry without the evidence rows (out of scope).

## Acceptance criteria

- [ ] The report JSON carries `evidence.count` equal to the number of ledger entries, with the root of
      the entry at that count; the HTML shows both; an engagement with no evidence pins
      `{root: null, count: 0}`.
- [ ] Each `GET /report` and `GET /report.html` writes one `report.exported` audit entry with the
      format and the pinned root and count.
- [ ] Posting a report's own `evidence` block back verifies `ok: true, issued: true,
      appended_since: 0`; after another run appends evidence, the same pin verifies with
      `appended_since > 0`.
- [ ] A pin whose root is not the chain's entry at `count` → `ok: false` with
      `broken_at = count` (`seq` is 1-based, so that is the entry at the pin) and the core's reason; a pin longer than the chain → `ok: false`
      ("entries were removed"); a tampered stored entry → `ok: false` at its `seq`.
- [ ] A well-formed pin this instance never exported (and that does not verify) → `issued: false`.
- [ ] Malformed bodies (bad hash, negative count, `root` null with `count > 0`, `root` set with
      `count 0`, non-integer count) → 422.
- [ ] A non-member → 403; a viewer may verify; a closed engagement can still be verified.
- [ ] `khandaq-core ledger-verify` exits 0 for an intact exported chain, 1 for a pin that no longer matches
      or for a tampered entry, and 2 for `--root` without `--count`.

## Test cases

Integration (`api/tests/test_report.py`):
`test_report_pins_root_and_count`, `test_report_export_is_audited` (JSON and HTML),
`test_report_verify_roundtrip` (`issued`, `appended_since` 0 then > 0 after a second run),
`test_report_verify_wrong_root`, `test_report_verify_pin_longer_than_chain`,
`test_report_verify_detects_tampering` (rewrites a stored `entry_hash` with the append-only trigger
disabled, as the spec 004 tamper test does), `test_report_verify_empty_pin`,
`test_report_verify_rejects_malformed` (parametrised), `test_report_verify_authz` (non-member 403,
viewer 200), `test_report_verify_closed_engagement`.
Rust (`core/khandaq-cli/tests/`): `ledger_verify_intact`, `ledger_verify_pin_mismatch`,
`ledger_verify_tampered`, `ledger_verify_requires_root_and_count_together`; fixtures built in the test
with `khandaq_core::ledger::append` (synthetic hashes only).
Security: the tampering and truncation cases above are the evidence-integrity negative tests; the
non-member 403 keeps the per-engagement authz invariant.

## Out of scope

- Hashing the whole report body so its findings section can be checked too: the report is not stored
  server-side; this belongs with signed report bundles (Sigstore, spec 004 follow-up).
- Recomputing each entry's `evidence_hash` offline from evidence bytes and metadata (needs the
  evidence bundle export, with the object-store upload of ADR-0006).
- A console view for re-verification (the console follow-ups for queued and failed runs).
- PDF export (spec 011).
