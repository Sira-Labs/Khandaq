# Spec 004 — Append-only, hash-chained evidence ledger

Sprint 2, story S2-2. Depends on: 001, 003. Packages: `core/` (ledger), `api/` (evidence), object store.

## Goal

Evidence artefacts are written append-only to the object store, encrypted at rest, and sealed into a
per-engagement hash-chained ledger that can be verified and whose root can be pinned into a report.
Nothing in the application can mutate or delete a sealed entry (ADR-0007).

## User story

As a compliance/governance lead, I want a tamper-evident evidence record so that a finding's proof holds
up after the engagement.

## Interface

Rust (`khandaq-core::ledger`): `append(engagement, evidence_hash) -> LedgerEntry`,
`verify(engagement) -> VerifyResult`, `root(engagement) -> RootHash`, `sign(root) -> Signature`
(Sigstore, optional). API: evidence is written via the run path (spec 005); `GET
/api/engagements/{id}/ledger` returns the chain + current root + verify status; `POST
/api/engagements/{id}/ledger/verify` re-verifies.

Config: `KHANDAQ_OBJECT_STORE_URL`, `KHANDAQ_OBJECT_STORE_*`, `KHANDAQ_EVIDENCE_KEY` (envelope key,
ADR-0006), `KHANDAQ_SIGSTORE=off|on`.

## Behaviour

1. Appending evidence stores the artefact (content-addressed, encrypted), then appends a `LedgerEntry`
   with `entry_hash = H(evidence_hash || prev_hash || seq)`; `seq` is contiguous per engagement.
2. `verify` recomputes the chain and reports the first break (if any) with its `seq`; a break is a
   high-severity reported condition.
3. `root` is the hash of the last entry; a report pins it. With Sigstore on, `sign` produces a
   verifiable signature over the root + manifest; it works offline when off.
4. The ledger API exposes no mutate/delete; the object store bucket is write-once for sealed objects.

## Acceptance criteria

- [x] Appending N evidence items yields a verifiable chain; `root` is stable until the next append.
- [x] Tampering with one stored entry is detected by `verify` at the right `seq`; deletion and
      reordering break the chain too (tests, Rust + API).
- [x] No code path mutates/deletes a sealed entry (the `ledger` module and API expose none).
- [~] Sigstore signing: **deferred** — the hash chain works fully offline (default); `KHANDAQ_SIGSTORE`
      is reserved and actual Sigstore signing lands as a follow-up (needs the sigstore toolchain/network).

> Notes (per CLAUDE.md): the Rust `ledger` module is pure (append/verify/root; `entry_hash =
> sha256(seq‖evidence_hash‖prev_hash)`); persistence lives in the API `ledger` service, which maps DB
> rows (evidence_id → Evidence.sha256) to core entries. Sigstore signing is deferred (follow-up in
> TASKS.md); everything else is offline and tested.

## Test cases

Rust property/unit (`core/khandaq-core/tests/ledger_*.rs`): chain build, verify catches tampering,
root stability, seq contiguity. Integration (`api/tests/test_evidence.py`): write evidence via a run,
fetch ledger, verify; redaction from spec 006 applies.

## Out of scope

Retention/erasure for data-protection (engagement-level destroy, documented in `deploy/`); external
notarisation beyond Sigstore.
