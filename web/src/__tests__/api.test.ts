import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- API client: CSRF and the dev header (spec 008 BFF) ------------------------------------------

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const SESSION_ME = {
  id: "usr_1",
  email: "alice@acme.test",
  display_name: "Alice",
  org_role: "member",
  csrf_token: "csrf-123",
  auth: "session",
};

describe("api client", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.resetModules();
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    localStorage.clear();
  });
  afterEach(() => vi.unstubAllGlobals());

  const sentHeaders = (call: number) =>
    (fetchMock.mock.calls[call][1] as RequestInit).headers as Record<string, string>;

  it("sends the session's CSRF token on mutations, never on reads", async () => {
    const { api } = await import("../api");
    fetchMock.mockResolvedValueOnce(json(200, SESSION_ME));
    fetchMock.mockResolvedValueOnce(json(200, []));
    fetchMock.mockResolvedValueOnce(json(201, { id: "eng_1" }));

    await api.me();
    await api.listEngagements();
    await api.createEngagement("Acme");

    expect(sentHeaders(1)["X-Khandaq-CSRF"]).toBeUndefined();
    expect(sentHeaders(2)["X-Khandaq-CSRF"]).toBe("csrf-123");
  });

  it("never sends the dev identity once the API reports a real session", async () => {
    const { api, setDevUser } = await import("../api");
    setDevUser("mallory@acme.test");
    fetchMock.mockResolvedValueOnce(json(200, SESSION_ME));
    fetchMock.mockResolvedValueOnce(json(200, []));

    await api.me();
    await api.listEngagements();

    expect(sentHeaders(1)["X-Khandaq-Dev-User"]).toBeUndefined();
  });

  it("keeps the dev identity in development", async () => {
    const { api, setDevUser } = await import("../api");
    setDevUser("dev@acme.test");
    fetchMock.mockResolvedValueOnce(json(200, { ...SESSION_ME, auth: "dev", csrf_token: null }));
    fetchMock.mockResolvedValueOnce(json(200, []));

    await api.me();
    await api.listEngagements();

    expect(sentHeaders(1)["X-Khandaq-Dev-User"]).toBe("dev@acme.test");
  });

  it("builds a login URL that only returns to a same-origin path", async () => {
    const { loginUrl } = await import("../api");
    expect(loginUrl("/eng/eng_1")).toBe("/api/auth/login?method=google&next=%2Feng%2Feng_1");
    expect(loginUrl("//evil.example")).toBe("/api/auth/login?method=google&next=%2F");
    expect(loginUrl("https://evil.example")).toBe("/api/auth/login?method=google&next=%2F");
    expect(loginUrl("/", "passkey")).toBe("/api/auth/login?method=passkey&next=%2F");
  });
});
