import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { api, type RunParams } from "../api";
import { CampaignsPanel } from "../components/CampaignsPanel";
import { ReportPanel } from "../components/ReportPanel";
import { RunsPanel } from "../components/RunsPanel";
import { SetupPanel } from "../components/SetupPanel";
import { navigate } from "../router";

export function Engagement({ engagementId }: { engagementId: string }) {
  const qc = useQueryClient();
  const eng = useQuery({ queryKey: ["eng", engagementId], queryFn: () => api.getEngagement(engagementId) });
  const targets = useQuery({ queryKey: ["targets", engagementId], queryFn: () => api.listTargets(engagementId) });
  const ledger = useQuery({ queryKey: ["ledger", engagementId], queryFn: () => api.ledger(engagementId) });

  const [targetId, setTargetId] = useState("");
  const [rate, setRate] = useState("");
  // A pre-flight answer is only valid for the exact target + params it checked (key below).
  // `error` means the check itself failed (network, CSRF, 5xx): no scope decision was made, so it
  // must not read as a denial.
  const [checked, setChecked] = useState<{
    key: string;
    allowed: boolean;
    reason: string | null;
    error?: string;
  } | null>(null);
  // The same params go to the pre-flight and the run, so what was checked is what runs. A rate is
  // required when the rules of engagement cap it (spec 002 §6). It must survive JSON as the number
  // typed: a long digit string becomes Infinity, which JSON sends as null.
  const rateValue = rate.trim() === "" ? null : Number(rate);
  const rateError =
    rateValue !== null && !(Number.isSafeInteger(rateValue) && rateValue > 0)
      ? "Enter a whole number of requests per minute, at least 1."
      : null;
  const params: RunParams = rateValue === null || rateError ? {} : { rate_per_minute: rateValue };
  const paramsKey = JSON.stringify(params);

  useEffect(() => {
    if (!targetId || rateError) {
      setChecked(null);
      return;
    }
    const key = `${targetId}|${paramsKey}`;
    let active = true;
    api
      .scopeCheck(engagementId, targetId, JSON.parse(paramsKey) as RunParams)
      .then((r) => {
        if (active) setChecked({ key, ...r });
      })
      .catch((err: Error) => {
        if (active) setChecked({ key, allowed: false, reason: null, error: err.message });
      });
    return () => {
      active = false;
    };
  }, [engagementId, targetId, paramsKey, rateError]);

  const preflight = checked && checked.key === `${targetId}|${paramsKey}` ? checked : null;

  const run = useMutation({
    mutationFn: () => api.createRun(engagementId, "echo", targetId, params),
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

      <SetupPanel engagement={eng.data} />

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
                {t.type}: {String((t.spec as { host?: string; url?: string }).url ?? (t.spec as { host?: string }).host ?? t.id)}
              </option>
            ))}
          </select>
          <input
            aria-label="rate per minute"
            className="w-28 rounded border border-white/15 bg-black/30 px-2 py-1 text-sm"
            inputMode="numeric"
            placeholder="rate / min"
            value={rate}
            onChange={(e) => setRate(e.target.value.replace(/[^0-9]/g, ""))}
          />
          <button
            className="rounded bg-[var(--ember)] px-4 py-1.5 font-medium text-black disabled:opacity-40"
            disabled={!targetId || !!rateError || preflight?.allowed !== true || run.isPending}
            onClick={() => run.mutate()}
          >
            Run
          </button>
        </div>
        {rateError && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            {rateError}
          </p>
        )}
        {preflight?.error && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            Pre-flight check failed: {preflight.error}. No scope decision was made; try again.
          </p>
        )}
        {preflight && !preflight.allowed && !preflight.error && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            Out of scope: {preflight.reason}
          </p>
        )}
        {preflight?.allowed && <p className="mt-2 text-sm text-green-400">In scope ✓</p>}
        {run.data?.state === "rejected" && (
          <p className="mt-2 text-sm text-red-400">Run rejected: {run.data.reject_reason}</p>
        )}
        {run.data?.state === "failed" && (
          <p className="mt-2 text-sm text-red-400">Run failed: {run.data.reject_reason}</p>
        )}
        {run.error && (
          <p className="mt-2 text-sm text-red-400" role="alert">
            Could not start the run: {run.error.message}
          </p>
        )}
      </section>

      <section className="grid gap-4 sm:grid-cols-2">
        <RunsPanel engagementId={engagementId} />
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

      <CampaignsPanel engagementId={engagementId} />

      <ReportPanel engagementId={engagementId} />

      <button className="text-[var(--ember)]" onClick={() => navigate(`/eng/${engagementId}/findings`)}>
        View findings →
      </button>
    </div>
  );
}
