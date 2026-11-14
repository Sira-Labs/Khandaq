import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, type Engagement, type Target } from "../api";
import { SetupPanel } from "../components/SetupPanel";

const api = vi.hoisted(() => ({
  me: vi.fn(),
  listTargets: vi.fn(),
  getScope: vi.fn(),
  setCredential: vi.fn(),
  clearCredential: vi.fn(),
}));

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, ...api } };
});

const KEY = "synthetic-console-key-0123456789"; // synthetic
const OWNER = { id: "usr_owner", email: "o@acme.test", display_name: "Owner", org_role: "member", csrf_token: "c", auth: "session" };
const ACTIVE: Engagement = {
  id: "eng_1",
  name: "ACME assistant",
  client: null,
  state: "active",
  owner_user_id: "usr_owner",
  authorisation_ref: "SOW-1",
};
const UNKEYED: Target = {
  id: "tgt_1",
  type: "llm_endpoint",
  spec: { url: "https://gw.acme.test/v1/chat/completions", model: "assistant-v3" },
  has_credential: false,
  credential_updated_at: null,
};
const KEYED: Target = { ...UNKEYED, has_credential: true, credential_updated_at: "2026-11-14T08:00:00Z" };

function show(engagement: Engagement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={qc}>
      <SetupPanel engagement={engagement} />
    </QueryClientProvider>,
  );
  return { qc, ...view };
}

/** Everything the page could have kept the key in: the DOM, both caches and web storage. */
function everywhere(qc: QueryClient, container: HTMLElement): string {
  const fields = [...container.querySelectorAll("input")].map((i) => i.value);
  return JSON.stringify([
    container.innerHTML,
    fields,
    qc.getQueryCache().getAll().map((q) => q.state),
    qc.getMutationCache().getAll().map((m) => m.state),
    { ...localStorage },
    { ...sessionStorage },
  ]);
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.me.mockResolvedValue(OWNER);
  api.listTargets.mockResolvedValue([UNKEYED]);
  api.getScope.mockResolvedValue(null);
});

describe("target credentials in the console (spec 028)", () => {
  it("lets the owner set a key through a password field and keeps it nowhere", async () => {
    api.setCredential.mockResolvedValue({ has_credential: true, version: 1, updated_at: KEYED.credential_updated_at });
    const { qc, container } = show(ACTIVE);

    expect(await screen.findByTestId("credential-status-tgt_1")).toHaveTextContent("no key");
    const field = (await screen.findByLabelText("API key for tgt_1")) as HTMLInputElement;
    expect(field.type).toBe("password");
    expect(field.autocomplete).toBe("new-password");
    expect(screen.queryByRole("button", { name: "Remove key" })).toBeNull();

    api.listTargets.mockResolvedValue([KEYED]);
    fireEvent.change(field, { target: { value: KEY } });
    fireEvent.click(screen.getByRole("button", { name: "Set key" }));

    await waitFor(() => expect(api.setCredential).toHaveBeenCalledWith("eng_1", "tgt_1", KEY));
    await waitFor(() =>
      expect(screen.getByTestId("credential-status-tgt_1")).toHaveTextContent("key set, updated 2026-11-14"),
    );
    expect((screen.getByLabelText("API key for tgt_1") as HTMLInputElement).value).toBe("");
    expect(everywhere(qc, container)).not.toContain(KEY);
  });

  it("replaces and removes a stored key", async () => {
    api.listTargets.mockResolvedValue([KEYED]);
    api.setCredential.mockResolvedValue({ has_credential: true, version: 2, updated_at: KEYED.credential_updated_at });
    api.clearCredential.mockResolvedValue(undefined);
    const { qc, container } = show(ACTIVE);

    fireEvent.change(await screen.findByLabelText("API key for tgt_1"), { target: { value: KEY } });
    fireEvent.click(screen.getByRole("button", { name: "Replace key" }));
    await waitFor(() => expect(api.setCredential).toHaveBeenCalledWith("eng_1", "tgt_1", KEY));

    api.listTargets.mockResolvedValue([UNKEYED]);
    fireEvent.click(screen.getByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(api.clearCredential).toHaveBeenCalledWith("eng_1", "tgt_1"));
    await waitFor(() => expect(screen.getByTestId("credential-status-tgt_1")).toHaveTextContent("no key"));
    expect(everywhere(qc, container)).not.toContain(KEY);
  });

  it("clears the field and shows the refusal when the API says no", async () => {
    api.setCredential.mockRejectedValue(new ApiError(503, "target credentials are not enabled on this deployment"));
    const { qc, container } = show(ACTIVE);

    fireEvent.change(await screen.findByLabelText("API key for tgt_1"), { target: { value: KEY } });
    fireEvent.click(screen.getByRole("button", { name: "Set key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not change the key: target credentials are not enabled on this deployment",
    );
    expect((screen.getByLabelText("API key for tgt_1") as HTMLInputElement).value).toBe("");
    expect(everywhere(qc, container)).not.toContain(KEY);
  });

  it("shows a non-owner the status only", async () => {
    api.me.mockResolvedValue({ ...OWNER, id: "usr_other" });
    api.listTargets.mockResolvedValue([KEYED]);
    show(ACTIVE);

    expect(await screen.findByTestId("credential-status-tgt_1")).toHaveTextContent("key set");
    expect(screen.queryByLabelText("API key for tgt_1")).toBeNull();
    expect(screen.queryByRole("button", { name: "Replace key" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove key" })).toBeNull();
  });

  it("offers the owner the key controls while the engagement is still a draft", async () => {
    show({ ...ACTIVE, state: "draft", authorisation_ref: null });
    expect(await screen.findByLabelText("API key for tgt_1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set key" })).toBeDisabled(); // nothing typed yet
  });

  it("offers nothing to edit on a closed engagement", async () => {
    show({ ...ACTIVE, state: "closed" });
    expect(await screen.findByTestId("credential-status-tgt_1")).toHaveTextContent("no key");
    expect(screen.queryByLabelText("API key for tgt_1")).toBeNull();
  });
});
