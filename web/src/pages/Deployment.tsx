import { useQuery } from "@tanstack/react-query";

import { ApiError, api, type SettingsSummary, type WorkerStatus } from "../api";
import { formatTime } from "../components/RunsPanel";
import { navigate } from "../router";

/** How often the page refreshes: the workers' heartbeat interval (spec 023). */
export const DEPLOYMENT_POLL_MS = 30_000;

function onOff(on: boolean | undefined): string {
  return on ? "on" : "off";
}

function alertChannels(summary: Partial<SettingsSummary>): string {
  const alerts = summary.alerts;
  if (!alerts) return "unknown";
  const on = Object.entries(alerts)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name);
  return on.length ? on.join(", ") : "none";
}

/** True when a worker labels findings with a different mapping table than the API (spec 024 §3). */
export function mappingMismatch(api: SettingsSummary, worker: Partial<SettingsSummary>): boolean {
  const theirs = worker.mappings;
  if (!theirs) return false; // an older worker that reports no summary yet
  const versions = JSON.stringify(Object.entries(api.mappings.versions).sort());
  const workerVersions = JSON.stringify(Object.entries(theirs.versions ?? {}).sort());
  return versions !== workerVersions || api.mappings.overlay?.sha256 !== theirs.overlay?.sha256;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-b border-white/5 py-1">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="text-right">{value}</dd>
    </div>
  );
}

function WorkerRow({ worker }: { worker: WorkerStatus }) {
  return (
    <tr className="border-b border-white/5" data-testid="worker-row">
      <td className="py-1 pr-3 font-mono text-xs">{worker.id}</td>
      <td className="pr-3">
        <span
          className={`rounded px-2 py-0.5 text-xs font-semibold text-white ${
            worker.alive ? "bg-green-700" : "bg-red-700"
          }`}
        >
          {worker.alive ? "alive" : "stale"}
        </span>
      </td>
      <td className="pr-3">{formatTime(worker.seen_at)}</td>
      <td className="pr-3">{formatTime(worker.started_at)}</td>
      <td className="pr-3">{worker.app_version}</td>
      <td>{alertChannels(worker.summary)}</td>
    </tr>
  );
}

/** Deployment status for organisation admins (spec 024): what the API and each worker run with,
 * and whether the workers are alive. Values are rendered as text; the endpoint returns no secret. */
export function Deployment() {
  const status = useQuery({
    queryKey: ["deployment"],
    queryFn: api.getDeployment,
    refetchInterval: DEPLOYMENT_POLL_MS,
    retry: (failures, err) => !(err instanceof ApiError && err.status === 403) && failures < 2,
  });

  const back = (
    <button className="text-sm text-[var(--muted)]" onClick={() => navigate("/")}>
      ← engagements
    </button>
  );
  if (status.error) {
    const forbidden = status.error instanceof ApiError && status.error.status === 403;
    return (
      <div className="space-y-4">
        {back}
        <p className="text-sm text-red-400" role="alert">
          {forbidden ? "Organisation admins only." : `Could not load the deployment status: ${status.error.message}`}
        </p>
      </div>
    );
  }
  if (!status.data) return <p className="text-[var(--muted)]">Loading…</p>;

  const { api: apiStatus, workers } = status.data;
  const s = apiStatus.summary;
  const alive = workers.filter((w) => w.alive);
  const mismatched = alive.filter((w) => mappingMismatch(s, w.summary));

  return (
    <div className="space-y-6">
      {back}
      <h1 className="text-2xl font-semibold">Deployment</h1>

      {alive.length === 0 && (
        <p className="text-sm text-red-400" role="alert">
          No worker has reported in the last 2 minutes: queued runs and campaigns will wait.
        </p>
      )}
      {mismatched.map((w) => (
        <p key={w.id} className="text-sm text-amber-300" role="alert">
          Worker {w.id} uses a different mapping table than the API: their findings would be labelled
          differently.
        </p>
      ))}

      <section className="rounded border border-white/10 p-4" data-testid="api-card">
        <h2 className="mb-2 font-semibold">API</h2>
        <dl className="text-sm">
          <Row label="version" value={apiStatus.app_version} />
          <Row label="schema" value={apiStatus.schema_revision} />
          <Row label="environment" value={s.env} />
          <Row label="evidence key" value={s.evidence.key ? "set" : "not set"} />
          <Row
            label="evidence store"
            value={s.evidence.bucket ? `${s.evidence.store} (${s.evidence.bucket})` : s.evidence.store}
          />
          <Row label="webhook alerts" value={onOff(s.alerts.webhook)} />
          <Row label="email alerts" value={onOff(s.alerts.email)} />
          <Row label="campaign interval floor" value={`${s.campaign_min_interval_minutes} min`} />
          <Row
            label="mapping tables"
            value={Object.entries(s.mappings.versions)
              .map(([fw, v]) => `${fw} ${v}`)
              .join(" · ")}
          />
          <Row
            label="mapping overlay"
            value={s.mappings.overlay ? `${s.mappings.overlay.name} (${s.mappings.overlay.sha256})` : "none"}
          />
        </dl>
      </section>

      <section className="rounded border border-white/10 p-4">
        <h2 className="mb-2 font-semibold">Workers</h2>
        <table className="w-full text-left text-sm">
          <thead className="text-[var(--muted)]">
            <tr>
              <th className="pr-3 font-normal">id</th>
              <th className="pr-3 font-normal">state</th>
              <th className="pr-3 font-normal">last seen</th>
              <th className="pr-3 font-normal">started</th>
              <th className="pr-3 font-normal">version</th>
              <th className="font-normal">alerts</th>
            </tr>
          </thead>
          <tbody>
            {workers.map((w) => (
              <WorkerRow key={w.id} worker={w} />
            ))}
            {workers.length === 0 && (
              <tr>
                <td colSpan={6} className="py-2 text-[var(--muted)]">
                  No worker has reported yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
