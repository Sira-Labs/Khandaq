import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getEngagement: vi.fn(async () => ({
        id: "eng_1", name: "Acme", client: null, state: "active",
        owner_user_id: "usr_1", authorisation_ref: "SOW-1",
      })),
      listTargets: vi.fn(async () => [{ id: "tgt_1", type: "llm_endpoint", spec: { host: "gw.acme.test" } }]),
      listRuns: vi.fn(async () => []),
      ledger: vi.fn(async () => ({ root: null, verify: { ok: true } })),
      scopeCheck: vi.fn(async () => ({ allowed: false, reason: "host 'gw.acme.test' is not in the allow-list" })),
      createRun: vi.fn(async () => ({ id: "run_1", adapter: "echo", state: "succeeded", reject_reason: null, target_id: "tgt_1" })),
    },
  };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

describe("Engagement run launcher", () => {
  it("blocks an out-of-scope launch with the reason (scope pre-flight)", async () => {
    const { Engagement } = await import("../pages/Engagement");
    render(wrap(<Engagement engagementId="eng_1" />));

    await screen.findByText("Acme");
    // Select the target → pre-flight runs → Run stays disabled and the reason is shown.
    const select = screen.getByLabelText("target") as HTMLSelectElement;
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.change(select, { target: { value: "tgt_1" } });

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Out of scope"));
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
  });

  it("shows a failed pre-flight instead of leaving Run stuck", async () => {
    const { api } = await import("../api");
    vi.mocked(api.scopeCheck).mockRejectedValueOnce(new Error("missing or invalid CSRF token"));
    const { Engagement } = await import("../pages/Engagement");
    const { fireEvent } = await import("@testing-library/react");
    render(wrap(<Engagement engagementId="eng_1" />));

    await screen.findByText("Acme");
    fireEvent.change(screen.getByLabelText("target"), { target: { value: "tgt_1" } });

    // A failed request is not a scope decision, so it must not read as "Out of scope".
    const alert = await screen.findByRole("alert");
    await waitFor(() =>
      expect(alert).toHaveTextContent("Pre-flight check failed: missing or invalid CSRF token"),
    );
    expect(alert).not.toHaveTextContent("Out of scope");
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
  });

  it("checks and runs with the same declared rate", async () => {
    const { api } = await import("../api");
    vi.mocked(api.scopeCheck).mockResolvedValue({ allowed: true, reason: null });
    const { Engagement } = await import("../pages/Engagement");
    const { fireEvent } = await import("@testing-library/react");
    render(wrap(<Engagement engagementId="eng_1" />));

    await screen.findByText("Acme");
    fireEvent.change(screen.getByLabelText("rate per minute"), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText("target"), { target: { value: "tgt_1" } });

    await waitFor(() =>
      expect(api.scopeCheck).toHaveBeenLastCalledWith("eng_1", "tgt_1", { rate_per_minute: 30 }),
    );
    const run = screen.getByRole("button", { name: "Run" });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);
    await waitFor(() =>
      expect(api.createRun).toHaveBeenCalledWith("eng_1", "echo", "tgt_1", { rate_per_minute: 30 }),
    );
  });

  it("does not let an approval for one rate authorise another", async () => {
    const { api } = await import("../api");
    vi.mocked(api.scopeCheck).mockImplementation(async (_e, _t, params) =>
      (params as { rate_per_minute?: number }).rate_per_minute === 30
        ? { allowed: true, reason: null }
        : new Promise(() => {}), // the new check has not answered yet
    );
    const { Engagement } = await import("../pages/Engagement");
    const { fireEvent } = await import("@testing-library/react");
    render(wrap(<Engagement engagementId="eng_1" />));

    await screen.findByText("Acme");
    fireEvent.change(screen.getByLabelText("rate per minute"), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText("target"), { target: { value: "tgt_1" } });
    const run = screen.getByRole("button", { name: "Run" });
    await waitFor(() => expect(run).toBeEnabled());

    fireEvent.change(screen.getByLabelText("rate per minute"), { target: { value: "999" } });
    expect(run).toBeDisabled(); // the approval was for 30/min, not 999/min
  });

  it("refuses a rate that cannot be sent as a number", async () => {
    const { api } = await import("../api");
    vi.mocked(api.scopeCheck).mockClear();
    vi.mocked(api.scopeCheck).mockResolvedValue({ allowed: true, reason: null });
    const { Engagement } = await import("../pages/Engagement");
    const { fireEvent } = await import("@testing-library/react");
    render(wrap(<Engagement engagementId="eng_1" />));

    await screen.findByText("Acme");
    // 400 digits: Number() gives Infinity, which JSON would send as null.
    fireEvent.change(screen.getByLabelText("rate per minute"), { target: { value: "9".repeat(400) } });
    fireEvent.change(screen.getByLabelText("target"), { target: { value: "tgt_1" } });

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("whole number"));
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();
    expect(api.scopeCheck).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("rate per minute"), { target: { value: "0" } });
    expect(screen.getByRole("alert")).toHaveTextContent("at least 1");
  });
});
