# ADR-0019: Target credentials are write-only, separately keyed, opt-in per adapter and redacted before sealing

- **Status:** Accepted (implementer, under ADR-0018; the stricter option was taken on each open
  point; the owner can reverse any of them with a new ADR)
- **Date:** 2026-11-14
- **Deciders:** implementer, for the owner. Details ADR-0006 for target credentials (spec 028).

## Context

ADR-0006 says target credentials are encrypted at rest, decrypted only at launch, injected as an
ephemeral environment value for the single run, and never written to logs, URLs, audit entries,
findings or evidence. Spec 028 was drafted on 2026-10-10 and waited for the owner to confirm five
design points. Under ADR-0018 the proposed, stricter value of each is taken and recorded here.

## Decision

1. **A key of its own.** Credentials are sealed under `KHANDAQ_CREDENTIAL_KEY`, never under
   `KHANDAQ_EVIDENCE_KEY`. Unset means the feature is off. Production refuses a placeholder, a key
   under 32 characters, or a key equal to the evidence key. Leaking or rotating one key never
   exposes or breaks what the other protects; losing the credential key loses only credentials,
   which owners enter again.
2. **No key over plain HTTP to a public-looking host.** A credential is refused for a target whose
   URL is `http` (or `ws`) and whose host has a dot in it, when it is stored and again just before
   it is injected. `https` and single-label service names inside the deployment network are
   allowed. A target without a URL cannot hold a credential.
3. **An adapter must opt in.** Only an adapter whose manifest declares `accepts_credential` is
   handed the key (`garak` today). For any other adapter the run proceeds without it and
   `run.started` records `not_accepted`; the Docker runner refuses to write a credential for an
   adapter that does not declare it.
4. **The old free-text field goes.** `targets.credential_ref` was never read. Migration 0012 sets
   it to `NULL` (someone may have pasted a secret into it), the API no longer returns it, and a
   target create that carries it is a 422 with a fixed message.
5. **Write-only, destroyed on close, and redacted before sealing.** No route returns a stored
   value. Closing an engagement deletes its credentials in the same transaction, each audited.
   After the adapter returns, the runner replaces every occurrence of the key (raw, percent-encoded
   in either case, or with a JSON-escaped solidus) by `[REDACTED:target-credential]` in findings,
   in every evidence file and in error text, **before** hashes are computed. The ledger therefore
   seals the redacted bytes, marked `redacted`, and the unredacted bytes are never stored.

Taken while implementing, in the same spirit:

- `run.started` records `credential: injected | none | not_accepted` when the run is claimed, and
  execution loads the key only if that entry says `injected`. A credential removed, undecryptable
  or no longer allowed to travel since then **fails the run**; it never falls back to the
  placeholder key, so the audit trail and what happened cannot disagree.
- Error text is redacted before it is cut to its recorded length; a cut through the key would leave
  a fragment that no longer matches.
- The credential request body is read untyped, and the old field is refused in the route, so that
  no validation error can echo a secret back.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Reuse the evidence key | One key to manage | One leak exposes both; rotation couples them | Decision 1 |
| Allow plain HTTP with a warning | Fewer refusals | A client's key crosses a network in the clear | Decision 2 |
| Inject into every adapter | Works without a manifest change | A wrapper that ignores or logs the key gets it anyway | Decision 3 |
| Keep unredacted evidence for privileged roles | Complete artefacts | The key would be stored, and sealed, for the engagement's life | Decision 5 |
| An external secrets manager | Stronger custody | Deployment friction for self-host (ADR-0006) | Later spec, optional |

## Consequences

- The evidence ledger, the scope lock and the audit log are unchanged: no sealed entry is modified,
  the key travels only through the per-run forwarder to the one in-scope host, and every credential
  change and injection is audited without the value.
- Evidence of a keyed run can differ from what the tool wrote by the redaction marker only; the
  `redacted` flag says where.
- Redaction covers the raw, percent-encoded and JSON-escaped forms. Other encodings (for example
  base64 inside a Basic header) are out of scope until a spec adds them; the value rule
  (`[A-Za-z0-9._~+/=:-]`, 8 to 1024 characters) keeps the key in a form those three cover.
- Each further adapter (PyRIT, promptfoo, mcp-scanner) adds `accepts_credential` in its own spec.
