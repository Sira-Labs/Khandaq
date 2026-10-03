# Spec 014 — Evidence encrypted at rest, in the object store, downloadable by role

Sprint 4, story S4-8. Depends on: 004, 008, 012. Packages: `api/` (evidence store, runs, routers),
`deploy/`. Decision record: ADR-0016 (envelope format); implements ADR-0006 for evidence.

## Goal

A container run's evidence bytes are stored encrypted (ADR-0016) and write-once, in the S3-compatible
object store when `KHANDAQ_OBJECT_STORE_URL` names one (RustFS in every bundled deployment), otherwise
in the worker's evidence directory. An owner, operator or analyst can download a piece of evidence;
the API decrypts it, checks it against its sealed hash, and records the download in the audit log.

## User story

As an analyst, I download the raw tool output behind a finding so that I can check the finding, and I
know the bytes are the ones that were sealed.

## Interface

- **Config.**

  | Key | Meaning | Default |
  |---|---|---|
  | `KHANDAQ_EVIDENCE_KEY` | KEK source, ≥ 32 characters (ADR-0016) | — (required to store evidence; prod requires it at boot) |
  | `KHANDAQ_EVIDENCE_PREVIOUS_KEYS` | retired keys, comma-separated, decrypt only | empty |
  | `KHANDAQ_OBJECT_STORE_URL` | `s3://<bucket>[/<prefix>]`; empty = local directory | empty |
  | `KHANDAQ_OBJECT_STORE_ENDPOINT` | S3 endpoint URL (RustFS / MinIO / AWS) | empty (AWS default) |
  | `KHANDAQ_OBJECT_STORE_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | S3 credentials | empty |
  | `KHANDAQ_OBJECT_STORE_REGION` | S3 region | `us-east-1` |
  | `KHANDAQ_EVIDENCE_DIR` | local store root (spec 012) | `/var/lib/khandaq/evidence` |

- **Modules.** `khandaq.evidence_crypto`: `Keyring.from_settings()`, `encrypt(object_key, plaintext)
  -> bytes`, `decrypt(object_key, blob) -> bytes`. `khandaq.evidence_store`: an `EvidenceStore`
  protocol (`put_new(key, blob)` raising `EvidenceExists`, `get(key)` raising `EvidenceMissing`),
  `LocalEvidenceStore`, `S3EvidenceStore` (boto3, client injected), `store_from_settings()`, and the
  service functions `retain(store, keyring, object_key, content, sha256)` and
  `read_verified(store, keyring, evidence) -> bytes`.
- **API.** `GET /api/engagements/{id}/evidence/{evidence_id}/content` → 200
  `application/octet-stream` with `Content-Disposition: attachment; filename="<evidence_id>-<name>"`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and `X-Khandaq-Evidence-Sha256`.
  Roles: `owner`, `operator`, `analyst`.
- **Audit.** `evidence.downloaded` `{evidence_id, sha256, bytes}`; `evidence.integrity_failed`
  `{evidence_id, reason}`.

## Behaviour

1. **Storing (worker, container runs).** For each evidence file, before it is sealed, the run path
   calls `retain`: it encrypts the bytes under the current key and `put_new`s the blob at the
   evidence's object key. No key configured → the run fails (`run.failed`, "KHANDAQ_EVIDENCE_KEY is
   not set"), and nothing is sealed. In-process adapters (`echo`) store no bytes, unchanged.
2. **Write-once.** `put_new` never overwrites. Local: temp file + hard link (spec 012). S3: a
   `HEAD` first, then `PUT` with `If-None-Match: *`; a 412 is `EvidenceExists`. On
   `EvidenceExists`, `retain` reads the stored object, decrypts it and compares sha256 with the
   value to seal: equal → accepted (a retried step), different → the run fails and nothing is
   overwritten.
3. **Bucket bootstrap.** On first use the S3 store checks the bucket; if it does not exist it creates
   it and tries to enable versioning (a failure to enable versioning is logged as a warning, since
   not every store supports it). Any other S3 error fails the run with the store's error code, never
   with credentials.
4. **Store selection.** Empty `KHANDAQ_OBJECT_STORE_URL` → local store. `s3://bucket[/prefix]` → S3
   store; object keys are `<prefix>/<object_key>`. Any other scheme → startup refuses in prod
   (`validate_runtime`) and the store factory raises in other envs.
5. **Downloading.** The route loads the evidence row from this engagement (another engagement's
   evidence id → 404). `read_verified` fetches the blob (missing → 404 "no stored content for this
   evidence"), decrypts it (unknown `kid`, bad tag → 409), and compares sha256 with the sealed
   `evidence.sha256` (mismatch → 409). A plaintext object from before this spec has no `KHQE`
   header; it is returned only if its sha256 matches the seal. On success it records
   `evidence.downloaded` and commits before responding; on a 409 it records
   `evidence.integrity_failed` instead. The error body never contains bytes, keys or credentials.
6. **Authz.** `viewer` → 403 (ADR-0006: unredacted artefacts only for authorised roles); non-member
   → 403; unknown engagement → 404; unauthenticated → 401. Downloading works in every engagement
   state.
7. **Config validation.** In prod, `KHANDAQ_EVIDENCE_KEY` shorter than 32 characters, or a retired
   key shorter than 32 characters, stops the app from starting.

## Acceptance criteria

Part 1 (encryption, local store, download):
- [ ] Round trip: `decrypt(key, encrypt(key, b))` returns `b`; a blob decrypted under another object
      key, with a flipped header byte, a flipped ciphertext byte, or an unknown `kid` raises.
- [ ] A retired key in `KHANDAQ_EVIDENCE_PREVIOUS_KEYS` decrypts its old objects; new writes use
      the current key.
- [ ] A container run stores ciphertext (no plaintext bytes on disk) and the ledger still verifies;
      an identical retry is accepted, different content under the same key fails.
- [ ] Without a key, a container run fails before sealing.
- [ ] `GET …/content` returns the original bytes with the documented headers and records
      `evidence.downloaded`; a viewer gets 403; another engagement's evidence id gets 404; echo
      evidence (no bytes) gets 404.
- [ ] A stored blob altered on disk → 409 and `evidence.integrity_failed`; a legacy plaintext file
      is served only when it matches the seal.
- [ ] Prod refuses a short evidence key.

Part 2 (object store):
- [ ] With `s3://bucket/prefix`, evidence goes to the S3 store under the prefix, via `If-None-Match`,
      after a `HEAD`; an existing object is never overwritten; a missing bucket is created.
- [ ] Download reads through the S3 store.
- [ ] An unsupported store URL is refused in prod and by the factory.
- [ ] `deploy/` documents the key (format, backup, rotation) and the object store.

## Test cases

Unit (`api/tests/test_evidence_crypto.py`): round trip, AAD binding, tamper cases, unknown kid,
rotation, short key refused. Unit (`api/tests/test_evidence_store.py`): local write-once, path escape,
`retain` idempotent retry and conflicting retry, legacy plaintext read, S3 store against an injected
fake client (bootstrap, HEAD-then-conditional-PUT, 412 → exists, prefix, error mapping), factory
selection. Integration (`api/tests/test_evidence_download.py`): container-run result persisted
through the run path with a key, download round trip + audit, viewer 403, cross-engagement 404, echo
404, tamper 409 + audit, no-key run failure.
Security: tamper, cross-engagement and viewer cases above; no test uses real credentials.

## Out of scope

- Re-encrypting existing objects under a new key (they are write-once; ADR-0016).
- Streaming encryption for artefacts larger than the adapter output cap.
- Redaction of secrets in raw output before display (ADR-0006; with the console evidence view).
- Target-credential encryption (ADR-0006; lands with credentialed targets).
- Object lock / retention policies on the bucket (deploy guidance only).
