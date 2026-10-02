## What

<!-- One or two sentences: what changes and why. Link the issue: Closes #123 -->

## Checks

- [ ] Implements a spec in `docs/specs/` (linked above); its acceptance criteria are ticked and `TASKS.md` is updated
- [ ] `make lint` and `make test` pass locally (or the relevant subset: `cargo`, `uv`, adapter `contract-test`, `pnpm`)
- [ ] Authorised-use controls preserved: the scope lock, the audit log and the evidence ledger still hold, with their tests
- [ ] No offensive payloads/exploit code added; adapters stay thin and version-pinned, with a contract test
- [ ] Findings still conform to the canonical schema (evidence refs, fingerprint, severity, framework mappings)
- [ ] Design deviations are recorded as a new ADR in `docs/adr/` (not silently)
- [ ] Docs updated (README, `deploy/README.md`, relevant `docs/`) where behaviour changed
- [ ] No secrets, credentials, live targets or captured evidence in code, config, fixtures or tests
- [ ] Commit messages follow `type(scope): summary` (feat, fix, docs, refactor, chore, test)

## Notes for the reviewer

<!-- Anything non-obvious: trade-offs, follow-ups, how to try it. -->
