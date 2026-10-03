import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, listTokens: vi.fn(), createToken: vi.fn(), revokeToken: vi.fn() },
  };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

const TOKENS = [
  { id: "tok_1", name: "ci", created_at: "2026-10-03T10:00:00Z", last_used_at: null, revoked_at: null },
  { id: "tok_2", name: "old", created_at: "2026-09-01T10:00:00Z", last_used_at: null, revoked_at: "2026-09-02T10:00:00Z" },
];

describe("API tokens page (spec 019)", () => {
  it("lists tokens, shows a new one once, and revokes", async () => {
    const { api } = await import("../api");
    vi.mocked(api.listTokens).mockResolvedValue(TOKENS);
    vi.mocked(api.createToken).mockResolvedValueOnce({ id: "tok_3", name: "smoke", token: "khq_synthetic_secret" });
    vi.mocked(api.revokeToken).mockResolvedValueOnce(undefined);
    const { Tokens } = await import("../pages/Tokens");
    render(wrap(<Tokens />));

    expect(await screen.findAllByTestId("token-row")).toHaveLength(2);
    expect(screen.getByText("revoked")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("token name"), { target: { value: "smoke" } });
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));
    expect(await screen.findByTestId("new-token")).toHaveTextContent("khq_synthetic_secret");
    expect(screen.getByRole("status")).toHaveTextContent("will not be shown again");
    expect(api.createToken).toHaveBeenCalledWith("smoke");

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.revokeToken).toHaveBeenCalledWith("tok_1"));
  });

  it("shows a refusal", async () => {
    const { api, ApiError } = await import("../api");
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockRejectedValueOnce(new ApiError(403, "missing or invalid CSRF token"));
    const { Tokens } = await import("../pages/Tokens");
    render(wrap(<Tokens />));

    await screen.findByText("No tokens.");
    fireEvent.change(screen.getByLabelText("token name"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("missing or invalid CSRF token");
  });
});
