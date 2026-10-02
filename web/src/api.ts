// API client for the Khandaq console. Same-origin; the dev-login email is sent as the
// X-Khandaq-Dev-User header until OIDC lands (spec 008), matching the API's dev-auth stub.

const DEV_USER_KEY = "khandaq-dev-user";

export function getDevUser(): string {
  try {
    return localStorage.getItem(DEV_USER_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setDevUser(email: string): void {
  try {
    localStorage.setItem(DEV_USER_KEY, email);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const dev = getDevUser();
  if (dev) headers["X-Khandaq-Dev-User"] = dev;
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "include",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      if (data?.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  const ct = res.headers.get("content-type") ?? "";
  return (ct.includes("application/json") ? await res.json() : undefined) as T;
}

export interface Engagement {
  id: string;
  name: string;
  client: string | null;
  state: string;
  owner_user_id: string;
  authorisation_ref: string | null;
}

export interface Target {
  id: string;
  type: string;
  spec: Record<string, unknown>;
}

export interface Finding {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string | null;
  severity: string;
  status: string;
  phase: string | null;
  mappings: { framework: string; id: string }[];
  evidence: string[];
  also_found_by: string[];
}

export interface Run {
  id: string;
  adapter: string;
  state: string;
  reject_reason: string | null;
  target_id: string | null;
}

export const api = {
  version: () => request<{ app: string; schema_revision: string }>("GET", "/version"),
  listEngagements: () => request<Engagement[]>("GET", "/engagements"),
  createEngagement: (name: string, client?: string) =>
    request<Engagement>("POST", "/engagements", { name, client }),
  getEngagement: (id: string) => request<Engagement>("GET", `/engagements/${id}`),
  listTargets: (id: string) => request<Target[]>("GET", `/engagements/${id}/targets`),
  getScope: (id: string) => request<Record<string, unknown> | null>("GET", `/engagements/${id}/scope`),
  listRuns: (id: string) => request<Run[]>("GET", `/engagements/${id}/runs`),
  listFindings: (id: string, severity?: string) =>
    request<Finding[]>("GET", `/engagements/${id}/findings${severity ? `?severity=${severity}` : ""}`),
  scopeCheck: (id: string, targetId: string, params: Record<string, unknown> = {}) =>
    request<{ allowed: boolean; reason: string | null }>("POST", `/engagements/${id}/scope-check`, {
      target_id: targetId,
      params,
    }),
  createRun: (id: string, adapter: string, targetId: string) =>
    request<Run>("POST", `/engagements/${id}/runs`, { adapter, target_id: targetId }),
  ledger: (id: string) =>
    request<{ root: string | null; verify: { ok: boolean; broken_at?: number } }>(
      "GET",
      `/engagements/${id}/ledger`,
    ),
};
