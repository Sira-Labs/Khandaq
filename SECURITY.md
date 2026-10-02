# Security policy

Khandaq orchestrates offensive security tooling against AI systems. Because of what it does,
security and safety are the product, not a feature. This policy covers both **vulnerabilities in
Khandaq** and the **safe-use expectations** for anyone running it.

## Authorised use only

Khandaq must only be used against AI systems you are **explicitly authorised** to test — your own,
or a client's under a signed engagement. Running offensive tooling against systems you do not have
permission to test is illegal in most jurisdictions.

Khandaq enforces this in code, and you must not circumvent it:

- Every run belongs to an **engagement** with declared in-scope targets and rules of engagement.
- The **scope lock** refuses targets outside the declared scope (server-side, tested).
- Every privileged action is written to an **append-only audit log**.

These controls are described in `docs/architecture/04-engagement-scope-and-authz.md`. A change
that weakens them is treated as a security defect.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
<https://github.com/Sira-Labs/Khandaq/security/advisories/new>.

Include the affected component (core, api, adapters, web, deploy), a version or commit, steps to
reproduce, and impact. You should hear back within 5 working days. We will keep you informed while
we triage, fix and publish an advisory, and credit you unless you prefer not.

Always in scope, and treated as high severity:

- A way to make a run reach a target **outside** the engagement's declared scope (scope-lock bypass).
- A way to perform a privileged action **without** an audit-log entry, or to alter/delete audit
  entries or a sealed evidence bundle (the ledger is hash-chained; a break in the chain that is
  not detected is in scope).
- Authentication or authorisation bypass in the API or web console.
- An adapter escaping its container isolation, or reading another engagement's evidence.
- Secrets (tokens, credentials, captured responses) leaking into logs, URLs or error messages.

## Supported versions

Khandaq is pre-1.0. Only the `main` branch and the most recent `v*` tag receive fixes.

## Scope

In scope: the code in this repository, the published container images (control plane and the
adapter images under `ghcr.io/sira-labs/khandaq-*`) and the deployment bundles in `deploy/`.

Out of scope: the upstream tools Khandaq orchestrates (garak, PyRIT, promptfoo, ART, scanners,
etc.) except where Khandaq's use of them is at fault; findings that require a compromised host or
administrator credentials; and the behaviour of a target system you point Khandaq at.

## Design notes for reporters

- No secrets in the repository; configuration comes from environment variables and production
  refuses placeholder values.
- Adapters run in isolated containers with no network access beyond the authorised, in-scope
  target; the control plane never executes attack payloads itself.
- Evidence is append-only and hash-chained (ADR-0007); any path that mutates sealed evidence is in
  scope.
- Images are built with SBOM and provenance attestations; `cargo audit`, `pip-audit` and
  `pnpm audit` run in CI.
