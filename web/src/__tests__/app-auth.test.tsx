import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api";

const SESSION_ME = {
  id: "usr_1",
  email: "alice@acme.test",
  display_name: "Alice",
  org_role: "member",
  csrf_token: "csrf-123",
  auth: "session",
};

// --- App shell: sign-in states ------------------------------------------------------------------

const meMock = vi.fn();

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, me: () => meMock(), listEngagements: vi.fn(async () => []) },
  };
});

async function renderApp() {
  const { App } = await import("../app");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <App />
    </QueryClientProvider>,
  );
}

describe("app sign-in", () => {
  beforeEach(() => {
    meMock.mockReset();
    window.history.replaceState(null, "", "/eng/eng_1");
  });

  it("offers sign-in (without auto-redirecting) when there is no session", async () => {
    meMock.mockRejectedValue(new ApiError(401, "authentication required"));
    await renderApp();
    const link = await screen.findByRole("link", { name: "Sign in" });
    expect(link).toHaveAttribute("href", "/api/auth/login?next=%2Feng%2Feng_1");
  });

  it("explains a refused account instead of looping back to the IdP", async () => {
    window.history.replaceState(null, "", "/?signin=denied");
    meMock.mockRejectedValue(new ApiError(401, "authentication required"));
    await renderApp();
    expect(await screen.findByRole("alert")).toHaveTextContent("no access");
    expect(screen.getByRole("link", { name: "Sign in with another account" })).toBeInTheDocument();
  });

  it("shows the signed-in user and sign-out, and no dev identity box", async () => {
    meMock.mockResolvedValue(SESSION_ME);
    await renderApp();
    expect(await screen.findByText("Alice")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
    expect(screen.queryByLabelText("dev user email")).toBeNull();
  });

  it("shows the dev identity box only in development", async () => {
    meMock.mockResolvedValue({ ...SESSION_ME, auth: "dev", csrf_token: null });
    await renderApp();
    expect(await screen.findByLabelText("dev user email")).toBeInTheDocument();
  });
});
