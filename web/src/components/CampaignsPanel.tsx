import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { navigate } from "../router";
import { formatTime } from "./RunsPanel";

/** An engagement's campaigns, and a form to start one (spec 018). The API enforces roles,
 * the interval floor and the scope lock; the panel shows its answer. */
export function CampaignsPanel({ engagementId }: { engagementId: string }) {
  const qc = useQueryClient();
  const campaigns = useQuery({
    queryKey: ["campaigns", engagementId],
    queryFn: () => api.listCampaigns(engagementId),
  });
  const targets = useQuery({ queryKey: ["targets", engagementId], queryFn: () => api.listTargets(engagementId) });

  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState("");
  const [interval, setInterval] = useState("60");
  const minutes = Number(interval);
  const intervalOk = Number.isSafeInteger(minutes) && minutes > 0;

  const create = useMutation({
    mutationFn: () =>
      api.createCampaign(engagementId, { name: name.trim(), adapter: "echo", target_id: targetId, interval_minutes: minutes }),
    onSuccess: () => {
      setName("");
      qc.invalidateQueries({ queryKey: ["campaigns", engagementId] });
    },
  });

  return (
    <section className="rounded border border-white/10 p-4">
      <h2 className="mb-2 font-semibold">Campaigns</h2>
      {campaigns.error && (
        <p className="text-sm text-red-400" role="alert">
          Could not load campaigns: {campaigns.error.message}
        </p>
      )}
      <ul className="space-y-1 text-sm">
        {campaigns.data?.map((c) => (
          <li key={c.id}>
            <button
              className="flex w-full items-center gap-2 text-left"
              onClick={() => navigate(`/eng/${engagementId}/campaigns/${c.id}`)}
            >
              <span
                className={`rounded px-2 py-0.5 text-xs font-semibold text-white ${c.enabled ? "bg-green-700" : "bg-slate-600"}`}
              >
                {c.enabled ? "enabled" : "paused"}
              </span>
              <span className="flex-1">{c.name}</span>
              <span className="text-xs text-[var(--muted)]">
                {c.adapter} · every {c.interval_minutes} min · next {formatTime(c.next_run_at)}
              </span>
            </button>
          </li>
        ))}
        {campaigns.data?.length === 0 && <li className="text-[var(--muted)]">No campaigns yet.</li>}
      </ul>

      <form
        className="mt-4 flex flex-wrap items-center gap-2 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <input
          aria-label="campaign name"
          className="rounded border border-white/15 bg-black/30 px-2 py-1"
          placeholder="campaign name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          aria-label="campaign target"
          className="rounded border border-white/15 bg-black/30 px-2 py-1"
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
        <span className="rounded bg-black/30 px-2 py-1">echo</span>
        <input
          aria-label="interval minutes"
          className="w-24 rounded border border-white/15 bg-black/30 px-2 py-1"
          inputMode="numeric"
          value={interval}
          onChange={(e) => setInterval(e.target.value.replace(/[^0-9]/g, ""))}
        />
        <span className="text-[var(--muted)]">min</span>
        <button
          type="submit"
          className="rounded bg-[var(--ember)] px-3 py-1 font-medium text-black disabled:opacity-40"
          disabled={!name.trim() || !targetId || !intervalOk || create.isPending}
        >
          New campaign
        </button>
      </form>
      {create.error && (
        <p className="mt-2 text-sm text-red-400" role="alert">
          Could not create the campaign: {create.error.message}
        </p>
      )}
    </section>
  );
}
