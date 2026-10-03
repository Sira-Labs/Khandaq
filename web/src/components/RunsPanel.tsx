import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { api, type Run } from "../api";

/** How often the runs list refreshes while a run is queued or running (spec 015 §2). */
export const RUN_POLL_MS = 5000;

const ACTIVE = new Set(["queued", "running"]);

const STATE_CLASS: Record<string, string> = {
  queued: "bg-slate-600",
  running: "bg-sky-700",
  succeeded: "bg-green-700",
  failed: "bg-red-700",
  rejected: "bg-amber-700",
};

/** Poll only while some run can still change state. */
export function runPollInterval(runs: Run[] | undefined): number | false {
  return runs?.some((r) => ACTIVE.has(r.state)) ? RUN_POLL_MS : false;
}

export function formatDuration(run: Run): string | null {
  if (!run.started_at || !run.ended_at) return null;
  const seconds = Math.max(0, Math.round((Date.parse(run.ended_at) - Date.parse(run.started_at)) / 1000));
  if (Number.isNaN(seconds)) return null;
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function formatTime(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function RunsPanel({ engagementId }: { engagementId: string }) {
  const qc = useQueryClient();
  const runs = useQuery({
    queryKey: ["runs", engagementId],
    queryFn: () => api.listRuns(engagementId),
    refetchInterval: (query) => runPollInterval(query.state.data),
  });

  // A run reaching a final state sealed evidence and stored findings: refresh what shows them.
  const active = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (!runs.data) return;
    const now = new Set(runs.data.filter((r) => ACTIVE.has(r.state)).map((r) => r.id));
    const finished = [...active.current].some((id) => !now.has(id));
    active.current = now;
    if (finished) {
      qc.invalidateQueries({ queryKey: ["ledger", engagementId] });
      qc.invalidateQueries({ queryKey: ["findings", engagementId] });
    }
  }, [runs.data, qc, engagementId]);

  return (
    <div className="rounded border border-white/10 p-4">
      <h2 className="mb-2 font-semibold">Runs</h2>
      {runs.error && (
        <p className="text-sm text-red-400" role="alert">
          Could not load runs: {runs.error.message}
        </p>
      )}
      <ul className="space-y-2 text-sm">
        {runs.data?.map((r) => {
          const duration = formatDuration(r);
          return (
            <li key={r.id} data-testid="run-row">
              <div className="flex items-center gap-2">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-semibold text-white ${STATE_CLASS[r.state] ?? "bg-slate-600"}`}
                >
                  {r.state}
                </span>
                <span className="flex-1">{r.adapter}</span>
                {duration && <span className="text-xs text-[var(--muted)]">{duration}</span>}
                <span className="text-xs text-[var(--muted)]">{formatTime(r.created_at)}</span>
              </div>
              {/* The reason can quote tool or target output: untrusted, rendered as text. */}
              {(r.state === "failed" || r.state === "rejected") && r.reject_reason && (
                <p className="mt-1 break-words text-xs text-red-300">{r.reject_reason}</p>
              )}
            </li>
          );
        })}
        {runs.data?.length === 0 && <li className="text-[var(--muted)]">No runs yet.</li>}
      </ul>
    </div>
  );
}
