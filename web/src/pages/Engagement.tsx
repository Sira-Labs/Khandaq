import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { api } from "../api";
import { navigate } from "../router";

export function Engagement({ engagementId }: { engagementId: string }) {
  const qc = useQueryClient();
  const eng = useQuery({ queryKey: ["eng", engagementId], queryFn: () => api.getEngagement(engagementId) });
  const targets = useQuery({ queryKey: ["targets", engagementId], queryFn: () => api.listTargets(engagementId) });
  const runs = useQuery({ queryKey: ["runs", engagementId], queryFn: () => api.listRuns(engagementId) });
  const ledger = useQuery({ queryKey: ["ledger", engagementId], queryFn: () => api.ledger(engagementId) });

  const [targetId, setTargetId] = useState("");
  const [preflight, setPreflight] = useState<{ allowed: boolean; reason: string | null } | null>(null);

  useEffect(() => {
    if (!targetId) {
      setPreflight(null);
      return;
    }
    let active = true;
    api.scopeCheck(engagementId, targetId).then((r) => {
      if (active) setPreflight(r);
    });
    return () => {
      active = false;
    };
  }, [engagementId, targetId]);

  const run = useMutation({
    mutationFn: () => api.createRun(engagementId, "echo", targetId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs", engagementId] });
      qc.invalidateQueries({ queryKey: ["ledger", engagementId] });
    },
  });

  if (eng.isLoading) return <p className="text-[var(--muted)]">Loading…</p>;
  if (eng.error || !eng.data) return <p className="text-red-400">No access to this engagement.</p>;

  return (
    <div className="space-y-6">
      <button className="text-sm text-[var(--muted)]" onClick={() => navigate("/")}>
        ← engagements
      </button>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{eng.data.name}</h1>
        <span className="text-xs uppercase text-[var(--muted)]">{eng.data.state}</span>
      </div>

      <section className="rounded border border-white/10 p-4">
        <h2 className="mb-2 font-semibold">Run a suite</h2>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm text-[var(--muted)]">adapter</span>
          <span className="rounded bg-black/30 px-2 py-1 text-sm">echo</span>
          <select
            aria-label="target"
            className="rounded border border-white/15 bg-black/30 px-2 py-1 text-sm"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
          >
            <option value="">select target…</option>
            {targets.data?.map((t) => (
              <option key={t.id} value={t.id}>
                {t.type}: {String((t.spec as { host?: string }).host ?? t.id)}
              </option>
            ))}
          </select>
          <button
            className="rounded bg-[var(--ember)] px-4 py-1.5 font-medium text-black disabled:opacity-40"
            disabled={!targetId || preflight?.allowed !== true || run.isPending}
            onClick={() => run.mutate()}
          >
            Run
          </button>
        </div>
        {preflight && !preflight.allowed && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            Out of scope: {preflight.reason}
          </p>
        )}
        {preflight?.allowed && <p className="mt-2 text-sm text-green-400">In scope ✓</p>}
        {run.data?.state === "rejected" && (
          <p className="mt-2 text-sm text-red-400">Run rejected: {run.data.reject_reason}</p>
        )}
      </section>

      <section className="grid gap-4 sm:grid-cols-2">
        <div className="rounded border border-white/10 p-4">
          <h2 className="mb-2 font-semibold">Runs</h2>
          <ul className="space-y-1 text-sm">
            {runs.data?.map((r) => (
              <li key={r.id} className="flex justify-between">
                <span>{r.adapter}</span>
                <span className="text-[var(--muted)]">{r.state}</span>
              </li>
            ))}
            {runs.data?.length === 0 && <li className="text-[var(--muted)]">No runs yet.</li>}
          </ul>
        </div>
        <div className="rounded border border-white/10 p-4">
          <h2 className="mb-2 font-semibold">Evidence ledger</h2>
          {ledger.data ? (
            <p className="text-sm">
              {ledger.data.verify.ok ? (
                <span className="text-green-400">intact ✓</span>
              ) : (
                <span className="text-red-400">broken at #{ledger.data.verify.broken_at}</span>
              )}
            </p>
          ) : (
            <p className="text-sm text-[var(--muted)]">—</p>
          )}
        </div>
      </section>

      <button className="text-[var(--ember)]" onClick={() => navigate(`/eng/${engagementId}/findings`)}>
        View findings →
      </button>
    </div>
  );
}
