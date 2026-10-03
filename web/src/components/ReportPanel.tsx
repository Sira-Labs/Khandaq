import { useState } from "react";

import { api, ApiError, saveDownload, type ReportPin, type ReportVerify } from "../api";

type Verdict =
  | { kind: "result"; result: ReportVerify; otherEngagement: string | null }
  | { kind: "error"; text: string };

/** The `evidence` pin and engagement id of an exported report, or null if it is not one. */
export function parseReport(text: string): { pin: ReportPin; engagementId: string | null } | null {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null) return null;
  const report = data as { evidence?: unknown; engagement?: { id?: unknown } };
  if (typeof report.evidence !== "object" || report.evidence === null) return null;
  const engagementId = typeof report.engagement?.id === "string" ? report.engagement.id : null;
  // Posted as is: the API validates the pin (and refuses a pre-013 report without a count).
  return { pin: report.evidence as ReportPin, engagementId };
}

function verdictText(r: ReportVerify): string {
  if (!r.ok) return `Evidence broken at #${r.verify.broken_at ?? "?"}: ${r.verify.reason ?? "verification failed"}`;
  const n = r.appended_since ?? 0;
  return `Evidence intact ✓ — ${n} entr${n === 1 ? "y" : "ies"} appended since`;
}

export function ReportPanel({ engagementId }: { engagementId: string }) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function exportReport(format: "json" | "html") {
    setError(null);
    try {
      saveDownload(await api.downloadReport(engagementId, format));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function verify(file: File) {
    setVerdict(null);
    try {
      // Reading the file can fail too (permissions, a vanished file): same error path as the API.
      const parsed = parseReport(await file.text());
      if (!parsed) {
        setVerdict({ kind: "error", text: "This file is not a Khandaq report export." });
        return;
      }
      const result = await api.verifyReport(engagementId, parsed.pin);
      const other = parsed.engagementId && parsed.engagementId !== engagementId ? parsed.engagementId : null;
      setVerdict({ kind: "result", result, otherEngagement: other });
    } catch (err) {
      const text =
        err instanceof ApiError && err.status === 422
          ? "This report has no ledger entry count (exported before re-verification existed) and cannot be verified."
          : err instanceof Error
            ? err.message
            : String(err);
      setVerdict({ kind: "error", text });
    }
  }

  return (
    <div className="rounded border border-white/10 p-4">
      <h2 className="mb-2 font-semibold">Report</h2>
      <div className="flex flex-wrap gap-2 text-sm">
        <button className="rounded border border-white/15 px-3 py-1" onClick={() => void exportReport("json")}>
          Download JSON
        </button>
        <button className="rounded border border-white/15 px-3 py-1" onClick={() => void exportReport("html")}>
          Download HTML
        </button>
      </div>
      {error && (
        <p className="mt-2 text-sm text-red-400" role="alert">
          Could not export the report: {error}
        </p>
      )}
      <label className="mt-4 block text-sm">
        <span className="text-[var(--muted)]">Verify a report (exported JSON)</span>
        <input
          aria-label="report file"
          className="mt-1 block text-sm"
          type="file"
          accept="application/json,.json"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void verify(file);
            e.target.value = "";
          }}
        />
      </label>
      {verdict?.kind === "error" && (
        <p className="mt-2 text-sm text-red-400" role="alert">
          {verdict.text}
        </p>
      )}
      {verdict?.kind === "result" && (
        <div className="mt-2 text-sm" role="status">
          <p className={verdict.result.ok ? "text-green-400" : "font-semibold text-red-400"}>
            {verdictText(verdict.result)}
          </p>
          <p className="text-[var(--muted)]">
            {verdict.result.issued ? "Issued by this instance." : "No export of this report on record here."}
          </p>
          {verdict.otherEngagement && (
            <p className="text-amber-300">
              This report names engagement {verdict.otherEngagement}; it was checked against this engagement's ledger.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
