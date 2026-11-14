# ADR-0018: Development continues in unattended nightly runs that merge their own green PRs

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** owner (order of 2026-11-14, recorded by the implementer)

## Context

Until now every session followed the protocol in `CLAUDE.md`: one spec, present a plan, wait for
the owner's approval, implement, and the owner merges. That stalls whenever the owner is away:
spec 028 waited five weeks for an approval, and about fifteen Dependabot PRs piled up. The owner
ordered on 2026-11-14 that development continues without him.

## Decision

A scheduled, unattended session ("nightly run") works the backlog under these rules. They override
older notes in the repository where the two disagree.

- **No waiting for approval.** Step 2 of the session protocol (present the plan, wait) is waived
  for nightly runs: plan, then implement. A deviation from a spec or an ADR is recorded as a new
  ADR in the same PR instead of a question.
- **The run merges.** It opens its PRs ready for review and enables auto-merge; where that is not
  possible it merges once every required check is green and every review thread is resolved. It
  never merges with a red or pending check.
- **Except the authorised-use controls.** A PR that changes how the scope lock, the audit log or
  the evidence ledger work (the paths `.github/CODEOWNERS` singles out, and any change to those
  mechanisms elsewhere) keeps the reviewer sign-off `CONTRIBUTING.md` requires, whatever branch
  protection enforces. The run opens it, gets it green, answers the review, and leaves it for the
  owner with an `Owner:` line in `TASKS.md`; it does not merge it and takes the next story.
- **One story per run**, in this order: its own open PRs and a broken `main` first; then
  Dependabot PRs (about a third of the run at most; adapter version pins and the ignore rules in
  `.github/dependabot.yml` are respected; a major bump that needs migration work becomes a backlog
  entry); then the first open, unblocked story in the plan's priority order.
- **Never stall on the owner.** A story that needs something only the owner can give (a secret, an
  account, a server, a licence, a product decision) gets one `Owner:` line in `TASKS.md` and the
  run takes the next story. Where an earlier session left a question with a recommended answer,
  the recommendation is taken, recorded (an ADR if it is hard to reverse) and reported.
- **Reporting.** Once a week (Sunday) the owner gets one mail with every open `Owner:` item and
  every decision a run took on his behalf since the last mail (accepted recommendations, new ADRs),
  including those that left no open item. Every run ends with a summary.

What does **not** change:

- The "Non-negotiable: authorised use" section of `CLAUDE.md` stays absolute. A nightly run never
  weakens the scope lock, the audit log or evidence integrity, adds no offensive payloads, exploit
  code or evasion techniques, uses synthetic data only, and runs tools only against the bundled
  local demo target. A story that would need any of that is blocked for the owner.
- A nightly run never deploys to or touches a production server, never cuts a major release, and
  never changes rulesets, branch protection, repository settings, tokens or workflow permissions.
  If branch protection requires a review the run cannot give, the PR waits for the owner.
- It never skips, disables or weakens a test or a lint rule to get green, never force-pushes to
  `main` and never rewrites someone else's branch.
- Spec first, tests, `make lint` and `make test` before each commit, semantic commits and the PR
  template apply as before.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Keep plan-and-wait for every spec | Owner sees every design first | Work stops when he is away | The stall this ADR removes |
| A GitHub automerge workflow | No session needed to merge | New workflow permissions; merges without anyone reading reviews | The run enables auto-merge per PR instead |
| **Unattended runs with fixed limits (chosen)** | Backlog moves; decisions are written down | Design choices are reviewed after the fact | Accepted; ADRs and the weekly mail keep them visible |

## Consequences

- Decisions taken without the owner are visible in three places: an ADR (when hard to reverse), the
  story's entry in `TASKS.md`, and the weekly mail. The owner can reverse any of them with a new ADR.
- `CLAUDE.md`, `CONTRIBUTING.md` and the sprint plan's working agreement point here.
- Interactive sessions with the owner present still follow the session protocol unchanged.
