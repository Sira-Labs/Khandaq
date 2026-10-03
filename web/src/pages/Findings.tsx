import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { api, type Finding } from "../api";
import { EvidenceList } from "../components/EvidenceList";
import { navigate } from "../router";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-amber-600",
  low: "bg-sky-700",
  info: "bg-slate-600",
};

export function Findings({ engagementId }: { engagementId: string }) {
  const [severity, setSeverity] = useState<string>("");
  const { data, isLoading, error } = useQuery({
    queryKey: ["findings", engagementId, severity],
    queryFn: () => api.listFindings(engagementId, severity || undefined),
  });
  const [selected, setSelected] = useState<Finding | null>(null);

  return (
    <div>
      <button className="mb-4 text-sm text-[var(--muted)]" onClick={() => navigate(`/eng/${engagementId}`)}>
        ← engagement
      </button>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <select
          aria-label="severity filter"
          className="rounded border border-white/15 bg-black/30 px-2 py-1 text-sm"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">all severities</option>
          {SEV_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {isLoading && <p className="text-[var(--muted)]">Loading…</p>}
      {error && (
        <p className="text-red-400" role="alert">
          Could not load findings: {error.message}
        </p>
      )}
      <ul className="divide-y divide-white/10">
        {data?.map((f) => (
          <li key={f.id}>
            <button className="flex w-full items-center gap-3 py-3 text-left" onClick={() => setSelected(f)}>
              <span className={`rounded px-2 py-0.5 text-xs font-semibold text-white ${SEV_CLASS[f.severity] ?? "bg-slate-600"}`}>
                {f.severity}
              </span>
              {/* Finding text is untrusted (attacker/model output); React escapes it. */}
              <span className="flex-1">{f.title ?? f.rule_id}</span>
              <span className="text-xs text-[var(--muted)]">
                {f.mappings.map((m) => m.id).join(", ")}
              </span>
              {f.also_found_by.length > 0 && (
                <span className="text-xs text-[var(--steel)]">+{f.also_found_by.length} tools</span>
              )}
            </button>
          </li>
        ))}
        {data?.length === 0 && <li className="py-3 text-[var(--muted)]">No findings.</li>}
      </ul>

      {selected && (
        <aside className="mt-6 rounded border border-white/15 bg-[var(--surface)] p-4" role="dialog" aria-label="finding detail">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-lg font-semibold">{selected.title ?? selected.rule_id}</h2>
            <button className="text-[var(--muted)]" onClick={() => setSelected(null)}>
              close
            </button>
          </div>
          <dl className="grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
            <dt className="text-[var(--muted)]">rule</dt>
            <dd>{selected.rule_id}</dd>
            <dt className="text-[var(--muted)]">severity</dt>
            <dd>{selected.severity}</dd>
            <dt className="text-[var(--muted)]">phase</dt>
            <dd>{selected.phase ?? "—"}</dd>
            <dt className="text-[var(--muted)]">frameworks</dt>
            <dd>{selected.mappings.map((m) => `${m.framework}:${m.id}`).join(", ") || "unmapped"}</dd>
            <dt className="text-[var(--muted)]">evidence</dt>
            <dd>
              <EvidenceList engagementId={engagementId} evidenceIds={selected.evidence} />
            </dd>
          </dl>
        </aside>
      )}
    </div>
  );
}
