# Deploying Khandaq

Three paths:

- **CapRover one-click** — the whole stack from one form (staging or a solo instance). See
  [`caprover/one-click/`](caprover/one-click/).
- **CapRover app-by-app** (staging + production with digest promotion), the family standard — see
  [`caprover.md`](caprover.md).
- **Single-box self-host** with `docker compose` for one operator on a trusted machine — below.

> The published images (`ghcr.io/sira-labs/khandaq-api`, `-web`, and the adapter images
> `ghcr.io/sira-labs/khandaq-adapter-*`) exist from **R1** onward. Until then this directory is the
> deployment design; the compose file and captain-definitions describe the target bundle.

## Single-box self-host

```bash
cd deploy
cp .env.example .env         # fill in secrets; prod refuses placeholders
docker compose up            # api, worker, postgres, rustfs, (optional) keycloak, + bundled target
```

This brings up the control plane, a Postgres, a RustFS object store for evidence, and the bundled
**intentionally-vulnerable local target** so you can run `make demo` without pointing at any third-party
system. Adapter containers are launched by the worker per run via the host Docker socket (shape A in
`caprover.md`); only use this on a trusted machine.

## What you must provide (ADR-0006)

- `KHANDAQ_SESSION_SECRET` — `openssl rand -base64 48`
- `KHANDAQ_EVIDENCE_KEY` — the envelope key that encrypts captured evidence at rest (**back this up
  separately; losing it makes evidence unreadable**)
- object-store credentials (RustFS root + a bucket-scoped key)
- OIDC settings for anything beyond a single-user local run

## Safe-use reminder

Khandaq runs offensive tooling. Every run must belong to an engagement whose targets you are authorised
to test; the scope lock enforces this. For demos and tests, use the **bundled vulnerable target** only —
never a third-party system. See `SECURITY.md`.

## Backups

For any real use, back up Postgres **and** the evidence object store (it holds the only copy of captured
evidence and the ledger proofs), plus the `KHANDAQ_EVIDENCE_KEY`. Production backup requirements are in
`caprover.md` section 7.
