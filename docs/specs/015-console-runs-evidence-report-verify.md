# Spec 015 — Console: run states, evidence download, report export and re-verification

Sprint 4, story S4-9. Depends on: 007, 012, 013, 014. Packages: `web/`.

## Goal

The console shows what the API already does since specs 012–014. Queued and running container runs
are visible and update themselves. A failed or rejected run shows why. A finding's evidence can be
downloaded. The report can be exported, and an exported report can be re-verified, with the verdict
spelled out. No API changes.

## User story

As an operator, I see my queued garak run start and finish without reloading the page, and if it
fails I see the reason. As an analyst, I download the raw output behind a finding. As a governance
lead, I drop in a report someone sent me and see whether its evidence is still intact.

## Interface

- **Runs panel** (engagement page): one row per run, newest first: adapter, a state badge (`queued`,
  `running`, `succeeded`, `failed`, `rejected`), when it was created, its duration once ended, and
  for `failed`/`rejected` the `reject_reason`. While any run is `queued` or `running` the list
  refetches every 5 s (`RUN_POLL_MS`); when a run reaches a final state, the ledger and findings
  queries are refreshed too.
- **Evidence in the finding drawer**: one row per evidence id with a **Download** button. It fetches
  `GET /api/engagements/{id}/evidence/{evidence_id}/content` with the console's credentials and saves
  the bytes under the server's file name. Never rendered in the page.
- **Report panel** (engagement page): **Download JSON** and **Download HTML** (both saved as files,
  never opened in the console's origin), and **Verify a report**: a file input that reads an exported
  report JSON, posts its `evidence` block to `POST /report/verify`, and shows the verdict.
- `api.ts`: `listRuns` returns the full `RunOut` (timestamps); `downloadEvidence(engagementId,
  evidenceId) -> {blob, filename}`; `downloadReport(engagementId, "json" | "html")`;
  `verifyReport(engagementId, pin) -> ReportVerify`.

## Behaviour

1. **Run states.** A badge per state; the reason text of a failed or rejected run is untrusted, so it
   is rendered as text (React escapes it). Duration = `ended_at − started_at` (seconds/minutes);
   absent while not ended.
2. **Polling.** `refetchInterval` is `RUN_POLL_MS` while some run is queued or running, else off. A
   run leaving `queued`/`running` invalidates `ledger` and `findings`.
3. **Evidence download.** On 200 the blob is saved through a temporary object URL (revoked
   right after). Errors are shown next to the row: 403 → "Your role cannot download raw evidence
   (owner, operator or analyst only)."; 404 → "No stored content for this evidence."; 409 →
   "Integrity check failed: the stored bytes do not match the sealed hash." (in red); anything else →
   the API's message.
4. **Report download.** Same mechanism; file names `khandaq-report-<engagement>.json|html`. The HTML
   is not opened in a tab: a blob URL would run in the console's origin.
5. **Verify a report.** The file must parse as JSON with an `evidence` object; otherwise "This file
   is not a Khandaq report export." The verdict:
   - `ok` → "Evidence intact ✓ — N entr(y|ies) appended since" plus "issued by this instance" or "no
     export on record here";
   - not `ok` → "Evidence broken at #seq: reason" (red);
   - 422 → "This report has no ledger entry count (exported before re-verification existed) and
     cannot be verified.";
   - other errors → the API's message.
   A report for another engagement is verified against this engagement's chain only if the user
   chose this engagement; the panel shows which engagement the file names when it differs.
6. **Security.** Nothing downloaded is rendered as HTML. Mutations (`POST /report/verify`) send the
   CSRF header like every other request.

## Acceptance criteria

- [ ] Runs panel shows badge, created time, duration and the failure/rejection reason; untrusted
      reason text is escaped.
- [ ] The runs query polls while a run is queued or running and stops when none is.
- [ ] Download buttons call the evidence endpoint and save a file; 403/404/409 show their messages.
- [ ] Report JSON/HTML download as files.
- [ ] Verify: intact verdict with appended count and issued flag; broken verdict with seq and reason;
      a pre-013 report shows the 422 message; a non-report file is refused before any request; an
      engagement mismatch is pointed out.
- [ ] `pnpm lint`, `pnpm test`, `pnpm build` pass.

## Test cases

`web/src/__tests__/runs.test.tsx`: badges + reason escaping, duration, polling on/off
(`refetchInterval` decision helper). `web/src/__tests__/evidence.test.tsx`: download success
(object URL created and revoked), 403/404/409 messages. `web/src/__tests__/report-verify.test.tsx`:
intact, broken, 422, not-a-report, engagement mismatch.

## Out of scope

- Launching container adapters from the console (the launcher stays `echo` until the adapters run
  their tools, spec 012 part 3).
- Rendering evidence or the report inside the console.
- Role-aware hiding of controls (the API enforces roles; the console shows its refusal).
