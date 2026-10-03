# ADR-0016: Evidence envelope format: a per-object AES-256-GCM key wrapped by a derived KEK

- **Status:** Proposed (implementer, spec 014; flagged for the owner)
- **Date:** 2026-10-03
- **Deciders:** implementer, while landing spec 014. It fills in ADR-0006's "evidence is encrypted
  at rest" and does not change ADR-0007's ledger formula.

## Context

ADR-0006 requires evidence to be encrypted at rest with a key from the environment. Spec 012 retains
container runs' evidence bytes in plaintext on the worker volume, and the object store the
deployments already configure (`KHANDAQ_OBJECT_STORE_URL=s3://khandaq-evidence`) is unused. Several
things constrain the format:

- `KHANDAQ_EVIDENCE_KEY` is already set on every deployment, in different shapes: the one-click
  generates 32 hex characters and `.env.example` says `openssl rand -base64 32`. Asking for one
  exact encoding would stop running deployments from starting.
- The ledger seals the plaintext's sha256 (ADR-0007/0014). The stored form must not change what is
  sealed, so a stored object can always be checked against its seal after decryption.
- Evidence is write-once. A retried run step must not overwrite an object, but random nonces make
  the ciphertext of a retry differ from the first write.
- Keys get rotated. Objects written under an old key must stay readable.

## Decision

- **Key encryption key (KEK).** HKDF-SHA256 over the UTF-8 `KHANDAQ_EVIDENCE_KEY`
  (salt `khandaq`, info `khandaq.evidence-kek/1`, 32 bytes). Any string of at least 32 characters is
  accepted, so existing keys keep working. The key id (`kid`) is the first 8 bytes of
  `sha256(KEK)`. `KHANDAQ_EVIDENCE_PREVIOUS_KEYS` (comma-separated) lists retired keys, which are
  used to decrypt only.
- **Per object.** A fresh 32-byte data key (DEK) and a 12-byte nonce. The DEK is wrapped with AES
  key wrap (RFC 3394) under the KEK. The plaintext is sealed with AES-256-GCM under the DEK. The AAD
  is the header plus the object key, so a blob moved to another key, or a header edited, fails to
  decrypt.
- **Layout (65-byte header, then ciphertext and tag):** `"KHQE"`, version byte `0x01`, `kid`
  (8 bytes), wrapped DEK (40 bytes), nonce (12 bytes), then `AES-GCM(plaintext)`.
- **Write-once.** Stores refuse to overwrite. When an object already exists, the writer decrypts it
  and accepts the write only if its sha256 equals the one about to be sealed. An identical retry
  passes; different content fails the run.
- **Reads verify.** Every read decrypts the object and compares its sha256 with the sealed
  `evidence.sha256` before returning bytes. A plaintext object written before spec 014 (no `KHQE`
  header) is still readable, and still checked against its seal.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Use the configured key directly as the AES key | No derivation step | Needs one exact encoding; today's keys differ in shape | Breaks running deployments |
| Server-side encryption in the object store (SSE-S3) | No code | Key held by the store, not by Khandaq; nothing for local files | ADR-0006 wants the key with the control plane |
| One key for every object, no DEK | Simpler | Rotation means re-encrypting everything; nonce reuse risk grows with volume | Envelope keeps rotation cheap |
| age / libsodium secretstream | Well-reviewed formats | New dependency; streaming not needed at today's sizes | `cryptography` is already a dependency (PyJWT) |

## Consequences

- Losing `KHANDAQ_EVIDENCE_KEY`, or a retired key still listed by some objects, makes that evidence
  unreadable. The seal still verifies, but the bytes are gone. The deploy docs say so and require a
  separate backup of the key.
- Rotation: set the new key, move the old one to `KHANDAQ_EVIDENCE_PREVIOUS_KEYS`. Objects are not
  re-encrypted (they are write-once), so a retired key stays listed for as long as its objects are
  kept.
- Evidence is read into memory (the adapter output cap, 256 MB by default, bounds it). Streaming
  encryption is a follow-up if larger artefacts appear.
