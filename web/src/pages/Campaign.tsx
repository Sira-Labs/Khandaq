import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { ApiError, api, type CampaignDiff, type DiffEntry } from "../api";
import { formatTime, RunList, runPollInterval } from "../components/RunsPanel";
import { navigate } from "../router";

function Entries({ label, entries, tone }: { label: string; entries: DiffEntry[]; tone: string }) {
  if (entries.length === 0) return null;
  return (
    <div className="mt-1">
      <p className={`text-xs font-semibold ${tone}`}>{label}</p>
      <ul className="ml-3 text-xs">
        {entries.map((e) => (
          <li key={e.fingerprint}>
            {/* Titles come from tool output: untrusted, rendered as text. */}
            <span className="text-[var(--muted)]">{e.severity}</span> {e.rule_id}
            {e.title ? ` — ${e.title}` : ""}
          </li>
        ))}
      </ul>
    </div>
  );
}

function DiffRow({ diff }: { diff: CampaignDiff }) {
  return (
    <li className="rounded border border-white/10 p-3" data-testid="diff-row">
      <div className="flex items-center gap-2 text-sm">
        {diff.baseline ? (
          <span className="rounded bg-slate-600 px-2 py-0.5 text-xs font-semibold text-white">baseline</span>
        ) : diff.worsened ? (
          <span className="rounded bg-red-700 px-2 py-0.5 text-xs font-semibold text-white">worsened</span>
        ) : (
          <span className="rounded bg-green-700 px-2 py-0.5 text-xs font-semibold text-white">no worse</span>
        )}
        <span className="flex-1 text-[var(--muted)]">
          {diff.baseline
            ? `${diff.findings_count} finding(s)`
            : `${diff.new.length} new · ${diff.regressed.length} regressed · ${diff.resolved.length} resolved · ${diff.unchanged_count} unchanged`}
        </span>
        <span className="text-xs text-[var(--muted)]">{formatTime(diff.created_at)}</span>
      </div>
      <Entries label="New" entries={diff.new} tone="text-red-300" />
      <Entries label="Regressed" entries={diff.regressed} tone="text-amber-300" />
      <Entries label="Resolved" entries={diff.resolved} tone="text-green-300" />
    </li>
  );
}

export function Campaign({ engagementId, campaignId }: { engagementId: string; campaignId: string }) {
  const qc = useQueryClient();
  const campaign = useQuery({
    queryKey: ["campaign", engagementId, campaignId],
    queryFn: () => api.getCampaign(engagementId, campaignId),
  });
  const runs = useQuery({
    queryKey: ["campaign-runs", engagementId, campaignId],
    queryFn: () => api.listCampaignRuns(engagementId, campaignId),
    refetchInterval: (query) => runPollInterval(query.state.data),
  });
  const diffs = useQuery({
    queryKey: ["campaign-diffs", engagementId, campaignId],
    queryFn: () => api.listCampaignDiffs(engagementId, campaignId),
  });
  const alerts = useQuery({
    queryKey: ["alerts", engagementId],
    queryFn: () => api.listAlerts(engagementId),
    retry: false,
  });

  // A campaign run finishing records its diff (and maybe an alert): refresh those.
  const active = useRef(0);
  useEffect(() => {
    const now = runs.data?.filter((r) => r.state === "queued" || r.state === "running").length ?? 0;
    if (now < active.current) {
      qc.invalidateQueries({ queryKey: ["campaign-diffs", engagementId, campaignId] });
      qc.invalidateQueries({ queryKey: ["alerts", engagementId] });
    }
    active.current = now;
  }, [runs.data, qc, engagementId, campaignId]);

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.updateCampaign(engagementId, campaignId, { enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["campaign", engagementId, campaignId] });
      qc.invalidateQueries({ queryKey: ["campaigns", engagementId] });
    },
  });

  if (campaign.isLoading) return <p className="text-[var(--muted)]">Loading…</p>;
  if (campaign.error || !campaign.data) return <p className="text-red-400">Campaign not found.</p>;
  const c = campaign.data;
  const alertsHidden = alerts.error instanceof ApiError && alerts.error.status === 403;
  const ownAlerts = alerts.data?.filter((a) => a.campaign_id === campaignId) ?? [];

  return (
    <div className="space-y-6">
      <button className="text-sm text-[var(--muted)]" onClick={() => navigate(`/eng/${engagementId}`)}>
        ← engagement
      </button>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{c.name}</h1>
          <p className="text-sm text-[var(--muted)]">
            {c.adapter} · every {c.interval_minutes} min · next run {formatTime(c.next_run_at)}
          </p>
        </div>
        <button
          className="rounded border border-white/15 px-3 py-1 text-sm disabled:opacity-40"
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(!c.enabled)}
        >
          {c.enabled ? "Pause" : "Resume"}
        </button>
      </div>
      {toggle.error && (
        <p className="text-sm text-red-400" role="alert">
          Could not change the campaign: {toggle.error.message}
        </p>
      )}

      <section className="rounded border border-white/10 p-4">
        <h2 className="mb-2 font-semibold">Diffs</h2>
        <ul className="space-y-2">
          {diffs.data?.map((d) => <DiffRow key={d.id} diff={d} />)}
          {diffs.data?.length === 0 && <li className="text-sm text-[var(--muted)]">No successful run yet.</li>}
        </ul>
      </section>

      <section className="rounded border border-white/10 p-4">
        <h2 className="mb-2 font-semibold">Runs</h2>
        {runs.data && <RunList runs={runs.data} />}
      </section>

      {!alertsHidden && (
        <section className="rounded border border-white/10 p-4">
          <h2 className="mb-2 font-semibold">Alerts</h2>
          <ul className="space-y-1 text-sm">
            {ownAlerts.map((a) => (
              <li key={a.id} className="flex gap-2" data-testid="alert-row">
                <span className="flex-1">{a.state}</span>
                <span className="text-xs text-[var(--muted)]">
                  {a.attempts} attempt(s){a.last_error ? ` · ${a.last_error}` : ""} · {formatTime(a.created_at)}
                </span>
              </li>
            ))}
            {ownAlerts.length === 0 && <li className="text-[var(--muted)]">No alerts.</li>}
          </ul>
        </section>
      )}
    </div>
  );
}
