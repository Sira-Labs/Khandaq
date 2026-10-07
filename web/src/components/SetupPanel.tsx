import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api, type Engagement, type ScopeIn, type Target, type TargetType } from "../api";

// Engagement setup in the console (spec 026): targets, a scope generated from them, activation.
// Every step goes through the spec 002 routes, so validation, the scope lock and the audit trail
// stay on the server; this panel only builds the requests and shows the API's answers.

const TYPES: { value: TargetType; label: string }[] = [
  { value: "llm_endpoint", label: "LLM endpoint" },
  { value: "agent", label: "Agent" },
  { value: "mcp_server", label: "MCP server" },
];

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return (u.protocol === "https:" || u.protocol === "http:") && !!u.hostname;
  } catch {
    return false;
  }
}

/** The allow rule that authorises one target: host, path and model for an endpoint or agent, the
 * exact URL for an MCP server. Returns null for a target this form cannot describe. */
function allowRule(t: Target): Record<string, unknown> | null {
  const spec = t.spec as { url?: string; base_url?: string; host?: string; model?: string; models?: string[] };
  if (t.type === "mcp_server") return typeof spec.url === "string" ? { url: spec.url } : null;
  if (t.type !== "llm_endpoint" && t.type !== "agent") return null;
  const url = spec.url ?? spec.base_url;
  let host = spec.host;
  let path: string | null = null;
  if (url && isHttpUrl(url)) {
    const u = new URL(url);
    host = host ?? u.hostname;
    path = u.pathname && u.pathname !== "/" ? u.pathname : null;
  }
  if (!host) return null;
  const rule: Record<string, unknown> = { host };
  if (path) rule.paths = [path];
  const models = spec.model ? [spec.model] : spec.models;
  if (models && models.length) rule.models = models;
  return rule;
}

/** The scope that allows exactly these targets, with an optional request-rate limit. */
export function scopeFromTargets(targets: Target[], ratePerMinute: number | null): ScopeIn {
  const allow: ScopeIn["allow"] = {};
  for (const t of targets) {
    const rule = allowRule(t);
    if (rule) (allow[t.type] ??= []).push(rule);
  }
  const roe = ratePerMinute ? { max_requests_per_minute: ratePerMinute } : {};
  return { allow, deny: [], roe };
}

function targetLabel(t: Target): string {
  const spec = t.spec as { url?: string; host?: string; model?: string };
  return `${t.type}: ${spec.url ?? spec.host ?? t.id}${spec.model ? ` (${spec.model})` : ""}`;
}

const box = "rounded border border-white/10 p-4";
const input = "rounded border border-white/15 bg-black/30 px-2 py-1 text-sm";
const primary = "rounded bg-[var(--ember)] px-4 py-1.5 text-sm font-medium text-black disabled:opacity-40";

export function SetupPanel({ engagement }: { engagement: Engagement }) {
  const id = engagement.id;
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const targets = useQuery({ queryKey: ["targets", id], queryFn: () => api.listTargets(id) });
  const scope = useQuery({ queryKey: ["scope", id], queryFn: () => api.getScope(id) });

  const [type, setType] = useState<TargetType>("llm_endpoint");
  const [url, setUrl] = useState("");
  const [model, setModel] = useState("");
  const [rate, setRate] = useState("");
  const [reference, setReference] = useState("");

  const urlError = url.trim() && !isHttpUrl(url.trim()) ? "Enter an absolute URL, e.g. https://gw.example.org/v1/chat" : null;
  const rateValue = rate.trim() === "" ? null : Number(rate);
  const rateError =
    rateValue !== null && !(Number.isSafeInteger(rateValue) && rateValue > 0)
      ? "Enter a whole number of requests per minute, at least 1."
      : null;
  const list = targets.data ?? [];
  const proposed = scopeFromTargets(list, rateError ? null : rateValue);
  const saved = scope.data ?? null;
  const stale =
    !!saved &&
    (JSON.stringify(saved.allow) !== JSON.stringify(proposed.allow) ||
      JSON.stringify(saved.roe) !== JSON.stringify(proposed.roe));

  const addTarget = useMutation({
    mutationFn: () => {
      const spec: Record<string, unknown> = { url: url.trim() };
      if (type !== "mcp_server" && model.trim()) spec.model = model.trim();
      return api.addTarget(id, type, spec);
    },
    onSuccess: () => {
      setUrl("");
      setModel("");
      qc.invalidateQueries({ queryKey: ["targets", id] });
    },
  });
  const saveScope = useMutation({
    mutationFn: () => api.setScope(id, proposed),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scope", id] }),
  });
  const activate = useMutation({
    mutationFn: () => api.activate(id, reference.trim()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["eng", id] });
      qc.invalidateQueries({ queryKey: ["scope", id] });
      qc.invalidateQueries({ queryKey: ["engagements"] });
    },
  });

  if (engagement.state !== "draft") {
    return (
      <section className={box} aria-label="Targets and scope">
        <h2 className="mb-2 font-semibold">
          Targets and scope{" "}
          {saved?.locked && <span className="text-xs font-normal text-green-400">locked</span>}
        </h2>
        <ul className="mb-2 space-y-1 text-sm">
          {list.map((t) => (
            <li key={t.id}>{targetLabel(t)}</li>
          ))}
        </ul>
        {saved && (
          <pre className="overflow-x-auto rounded bg-black/30 p-2 text-xs text-[var(--steel)]">
            {JSON.stringify({ allow: saved.allow, deny: saved.deny, roe: saved.roe }, null, 2)}
          </pre>
        )}
        {engagement.authorisation_ref && (
          <p className="mt-2 text-sm text-[var(--muted)]">Authorisation: {engagement.authorisation_ref}</p>
        )}
      </section>
    );
  }

  if (me.data && me.data.id !== engagement.owner_user_id) {
    return (
      <section className={box} aria-label="Set up this engagement">
        <h2 className="mb-2 font-semibold">Set up this engagement</h2>
        <p className="text-sm text-[var(--muted)]">
          Only the engagement owner can set up targets, scope and activation.
        </p>
      </section>
    );
  }

  return (
    <section className={`${box} space-y-5`} aria-label="Set up this engagement">
      <div>
        <h2 className="font-semibold">Set up this engagement</h2>
        <p className="text-sm text-[var(--muted)]">
          A draft runs nothing. Add the targets you are authorised to test, save their scope, then
          activate with the authorisation reference; activation locks the scope.
        </p>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold">1. Targets</h3>
        {list.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No targets yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {list.map((t) => (
              <li key={t.id}>{targetLabel(t)}</li>
            ))}
          </ul>
        )}
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (url.trim() && !urlError) addTarget.mutate();
          }}
        >
          <select aria-label="target type" className={input} value={type} onChange={(e) => setType(e.target.value as TargetType)}>
            {TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
          <input
            aria-label="target URL"
            className={`${input} min-w-0 flex-1`}
            placeholder="https://gw.example.org/v1/chat/completions"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          {type !== "mcp_server" && (
            <input
              aria-label="model"
              className={`${input} w-40`}
              placeholder="model (optional)"
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
          )}
          <button className={primary} disabled={!url.trim() || !!urlError || addTarget.isPending}>
            Add target
          </button>
        </form>
        {urlError && <p className="text-sm text-red-400">{urlError}</p>}
        {addTarget.error && (
          <p className="text-sm text-red-400" role="alert">
            Could not add the target: {addTarget.error.message}
          </p>
        )}
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold">2. Scope</h3>
        <p className="text-sm text-[var(--muted)]">
          The scope allows exactly the targets above. Anything else is refused before a run starts.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            aria-label="maximum requests per minute"
            className={`${input} w-56`}
            inputMode="numeric"
            placeholder="max requests / min (optional)"
            value={rate}
            onChange={(e) => setRate(e.target.value.replace(/[^0-9]/g, ""))}
          />
          <button
            className={primary}
            disabled={list.length === 0 || !!rateError || saveScope.isPending}
            onClick={() => saveScope.mutate()}
          >
            Save scope
          </button>
          {saved && !stale && <span className="text-sm text-green-400">Saved ✓</span>}
        </div>
        {rateError && <p className="text-sm text-red-400">{rateError}</p>}
        {list.length > 0 && (
          <pre aria-label="scope preview" className="overflow-x-auto rounded bg-black/30 p-2 text-xs text-[var(--steel)]">
            {JSON.stringify(proposed, null, 2)}
          </pre>
        )}
        {stale && (
          <p className="text-sm text-amber-300">
            The saved scope does not match these targets yet. Save the scope again to include them.
          </p>
        )}
        {saveScope.error && (
          <p className="text-sm text-red-400" role="alert">
            Could not save the scope: {saveScope.error.message}
          </p>
        )}
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold">3. Activate</h3>
        <div className="flex flex-wrap items-center gap-2">
          <input
            aria-label="authorisation reference"
            className={`${input} min-w-0 flex-1`}
            placeholder="Authorisation reference, e.g. SOW-2026-114, signed 1 Oct 2026"
            value={reference}
            onChange={(e) => setReference(e.target.value)}
          />
          <button
            className={primary}
            disabled={!saved || stale || !reference.trim() || activate.isPending}
            onClick={() => activate.mutate()}
          >
            Activate
          </button>
        </div>
        {activate.error && (
          <p className="text-sm text-red-400" role="alert">
            Could not activate: {activate.error.message}
          </p>
        )}
      </div>
    </section>
  );
}
