// API client for the Khandaq console (same origin, behind the web app's /api proxy).
//
// Production sign-in is the OIDC backend-for-frontend of spec 008: the browser holds only the
// server's session cookie, and every state-changing request must echo the session's CSRF token in
// X-Khandaq-CSRF. `me()` loads that token. The X-Khandaq-Dev-User header is the development stub
// only — the API ignores it in production — and is sent only while the API reports `auth: "dev"`.

const DEV_USER_KEY = "khandaq-dev-user";
const CSRF_HEADER = "X-Khandaq-CSRF";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

let csrfToken: string | null = null;
let devMode = false;

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

/** Where the "Sign in" button goes: the API starts the OIDC login and returns to `next`. */
export function loginUrl(next: string): string {
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  return `/api/auth/login?next=${encodeURIComponent(safeNext)}`;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const dev = getDevUser();
  if (devMode && dev) headers["X-Khandaq-Dev-User"] = dev;
  if (!SAFE_METHODS.has(method) && csrfToken) headers[CSRF_HEADER] = csrfToken;
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
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

export interface Me {
  id: string;
  email: string;
  display_name: string | null;
  org_role: string;
  csrf_token: string | null;
  auth: "session" | "token" | "dev";
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

export type RunParams = Record<string, unknown>;

export const api = {
  /** Who is signed in; also loads the CSRF token every later mutation needs. */
  me: async () => {
    devMode = true; // let the dev identity through for this probe; the answer decides from here on
    try {
      const me = await request<Me>("GET", "/auth/me");
      csrfToken = me.csrf_token;
      devMode = me.auth === "dev";
      return me;
    } catch (err) {
      devMode = false;
      csrfToken = null;
      throw err;
    }
  },
  logout: () => request<{ status: string }>("POST", "/auth/logout"),
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
  scopeCheck: (id: string, targetId: string, params: RunParams = {}) =>
    request<{ allowed: boolean; reason: string | null }>("POST", `/engagements/${id}/scope-check`, {
      target_id: targetId,
      params,
    }),
  createRun: (id: string, adapter: string, targetId: string, params: RunParams = {}) =>
    request<Run>("POST", `/engagements/${id}/runs`, { adapter, target_id: targetId, params }),
  ledger: (id: string) =>
    request<{ root: string | null; verify: { ok: boolean; broken_at?: number } }>(
      "GET",
      `/engagements/${id}/ledger`,
    ),
};
