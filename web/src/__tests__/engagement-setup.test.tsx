import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, type Engagement, type Scope, type Target } from "../api";
import { SetupPanel, scopeFromTargets } from "../components/SetupPanel";

const api = vi.hoisted(() => ({
  me: vi.fn(),
  listTargets: vi.fn(),
  getScope: vi.fn(),
  addTarget: vi.fn(),
  setScope: vi.fn(),
  activate: vi.fn(),
}));

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, ...api } };
});

const OWNER = { id: "usr_owner", email: "o@acme.test", display_name: "Owner", org_role: "admin", csrf_token: "c", auth: "session" };
const DRAFT: Engagement = {
  id: "eng_1",
  name: "ACME assistant",
  client: null,
  state: "draft",
  owner_user_id: "usr_owner",
  authorisation_ref: null,
};
const ENDPOINT: Target = {
  id: "tgt_1",
  type: "llm_endpoint",
  spec: { url: "https://gw.acme.test/v1/chat/completions", model: "assistant-v3" },
};
const ENDPOINT_SCOPE = {
  allow: { llm_endpoint: [{ host: "gw.acme.test", paths: ["/v1/chat/completions"], models: ["assistant-v3"] }] },
  deny: [],
  roe: {},
};

function show(engagement: Engagement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <SetupPanel engagement={engagement} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.me.mockResolvedValue(OWNER);
  api.listTargets.mockResolvedValue([]);
  api.getScope.mockResolvedValue(null);
});

describe("scopeFromTargets", () => {
  it("allows an endpoint by host, path and model, and an MCP server by its exact URL", () => {
    const mcp: Target = { id: "tgt_2", type: "mcp_server", spec: { url: "https://tools.acme.test/mcp" } };
    expect(scopeFromTargets([ENDPOINT, mcp], null)).toEqual({
      allow: { ...ENDPOINT_SCOPE.allow, mcp_server: [{ url: "https://tools.acme.test/mcp" }] },
      deny: [],
      roe: {},
    });
  });

  it("puts a rate into the rules of engagement and handles host-only targets", () => {
    const hostOnly: Target = { id: "tgt_3", type: "agent", spec: { host: "agent.acme.test" } };
    expect(scopeFromTargets([hostOnly], 60)).toEqual({
      allow: { agent: [{ host: "agent.acme.test" }] },
      deny: [],
      roe: { max_requests_per_minute: 60 },
    });
  });
});

describe("engagement setup panel", () => {
  it("adds a target with the URL and model the owner typed", async () => {
    api.addTarget.mockResolvedValue(ENDPOINT);
    show(DRAFT);
    fireEvent.change(await screen.findByLabelText("target URL"), { target: { value: "https://gw.acme.test/v1/chat/completions" } });
    fireEvent.change(screen.getByLabelText("model"), { target: { value: "assistant-v3" } });
    fireEvent.click(screen.getByRole("button", { name: "Add target" }));
    await waitFor(() =>
      expect(api.addTarget).toHaveBeenCalledWith("eng_1", "llm_endpoint", {
        url: "https://gw.acme.test/v1/chat/completions",
        model: "assistant-v3",
      }),
    );
  });

  it("refuses a URL that is not absolute before calling the API", async () => {
    show(DRAFT);
    fireEvent.change(await screen.findByLabelText("target URL"), { target: { value: "gw.acme.test" } });
    expect(screen.getByText(/Enter an absolute URL/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add target" })).toBeDisabled();
  });

  it("saves the generated scope, with a rate, and shows it", async () => {
    api.listTargets.mockResolvedValue([ENDPOINT]);
    api.setScope.mockResolvedValue({ engagement_id: "eng_1", version: 1, locked: false, ...ENDPOINT_SCOPE });
    show(DRAFT);
    fireEvent.change(await screen.findByLabelText("maximum requests per minute"), { target: { value: "60" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Save scope" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Save scope" }));
    await waitFor(() =>
      expect(api.setScope).toHaveBeenCalledWith("eng_1", { ...ENDPOINT_SCOPE, roe: { max_requests_per_minute: 60 } }),
    );
  });

  it("enables Activate only with a saved, current scope and a reference", async () => {
    api.listTargets.mockResolvedValue([ENDPOINT]);
    api.getScope.mockResolvedValue({ engagement_id: "eng_1", version: 1, locked: false, ...ENDPOINT_SCOPE } satisfies Scope);
    api.activate.mockResolvedValue({ ...DRAFT, state: "active" });
    show(DRAFT);
    const activate = await screen.findByRole("button", { name: "Activate" });
    await screen.findByText("Saved ✓");
    expect(activate).toBeDisabled();
    fireEvent.change(screen.getByLabelText("authorisation reference"), { target: { value: "SOW-2026-114" } });
    expect(activate).toBeEnabled();
    fireEvent.click(activate);
    await waitFor(() => expect(api.activate).toHaveBeenCalledWith("eng_1", "SOW-2026-114"));
  });

  it("keeps Activate off while the saved scope misses a target", async () => {
    const mcp: Target = { id: "tgt_2", type: "mcp_server", spec: { url: "https://tools.acme.test/mcp" } };
    api.listTargets.mockResolvedValue([ENDPOINT, mcp]);
    api.getScope.mockResolvedValue({ engagement_id: "eng_1", version: 1, locked: false, ...ENDPOINT_SCOPE });
    show(DRAFT);
    expect(await screen.findByText(/Save the scope again/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("authorisation reference"), { target: { value: "SOW-2026-114" } });
    expect(screen.getByRole("button", { name: "Activate" })).toBeDisabled();
  });

  it("shows the API's refusal", async () => {
    api.addTarget.mockRejectedValue(new ApiError(422, "an mcp_server target needs an absolute 'url'"));
    show(DRAFT);
    fireEvent.change(await screen.findByLabelText("target type"), { target: { value: "mcp_server" } });
    expect(screen.queryByLabelText("model")).toBeNull();
    fireEvent.change(screen.getByLabelText("target URL"), { target: { value: "https://tools.acme.test/mcp" } });
    fireEvent.click(screen.getByRole("button", { name: "Add target" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not add the target: an mcp_server target needs");
  });

  it("shows no controls to someone who is not the owner", async () => {
    api.me.mockResolvedValue({ ...OWNER, id: "usr_other" });
    show(DRAFT);
    expect(await screen.findByText(/Only the engagement owner/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add target" })).toBeNull();
  });

  it("shows targets and the locked scope read-only once active", async () => {
    api.listTargets.mockResolvedValue([ENDPOINT]);
    api.getScope.mockResolvedValue({ engagement_id: "eng_1", version: 1, locked: true, ...ENDPOINT_SCOPE });
    show({ ...DRAFT, state: "active", authorisation_ref: "SOW-2026-114" });
    expect(await screen.findByText("locked")).toBeInTheDocument();
    expect(screen.getByText(/llm_endpoint: https:\/\/gw.acme.test/)).toBeInTheDocument();
    expect(screen.getByText("Authorisation: SOW-2026-114")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Activate" })).toBeNull();
  });
});
