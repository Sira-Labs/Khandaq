import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, type DeploymentStatus, type SettingsSummary } from "../api";

const meMock = vi.fn();

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      me: () => meMock(),
      getDeployment: vi.fn(),
      listEngagements: vi.fn(async () => []),
    },
  };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

const SUMMARY: SettingsSummary = {
  role: "api",
  env: "prod",
  evidence: { key: true, retired_keys: 0, store: "s3", bucket: "khandaq-evidence" },
  alerts: { webhook: false, email: false },
  campaign_min_interval_minutes: 60,
  mappings: { versions: { atlas: "v2026.09", "nist-ai-rmf": "1.0" }, overlay: null },
  adapter_runtime: "docker-socket",
};

function status(workers: DeploymentStatus["workers"]): DeploymentStatus {
  return {
    checked_at: "2026-10-03T14:30:00Z",
    api: { app_version: "0.1.0", schema_revision: "0011_worker_heartbeats", summary: SUMMARY },
    workers,
  };
}

const WORKER = {
  id: "srv-captain--khandaq-stg-worker:1",
  started_at: "2026-10-03T14:00:00Z",
  seen_at: "2026-10-03T14:29:45Z",
  alive: true,
  app_version: "0.1.0",
  summary: { ...SUMMARY, role: "worker", alerts: { webhook: true, email: true } },
};

describe("Deployment page (spec 024)", () => {
  it("shows the API card and an alive worker with its alerts", async () => {
    const { api } = await import("../api");
    vi.mocked(api.getDeployment).mockResolvedValue(status([WORKER]));
    const { Deployment } = await import("../pages/Deployment");
    render(wrap(<Deployment />));

    const [row] = await screen.findAllByTestId("worker-row");
    expect(row).toHaveTextContent("alive");
    expect(row).toHaveTextContent("webhook, email");
    const card = screen.getByTestId("api-card");
    expect(card).toHaveTextContent("0011_worker_heartbeats");
    expect(card).toHaveTextContent("s3 (khandaq-evidence)");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("warns when no worker is alive", async () => {
    const { api } = await import("../api");
    vi.mocked(api.getDeployment).mockResolvedValue(status([{ ...WORKER, alive: false }]));
    const { Deployment } = await import("../pages/Deployment");
    render(wrap(<Deployment />));

    expect(await screen.findByRole("alert")).toHaveTextContent("No worker has reported in the last 2 minutes");
    expect(screen.getByTestId("worker-row")).toHaveTextContent("stale");
  });

  it("warns when a worker uses a different mapping overlay", async () => {
    const { api } = await import("../api");
    const overlaid = {
      ...WORKER,
      summary: {
        ...WORKER.summary,
        mappings: { ...SUMMARY.mappings, overlay: { name: "acme.json", sha256: "sha256:abc" } },
      },
    };
    vi.mocked(api.getDeployment).mockResolvedValue(status([overlaid]));
    const { Deployment } = await import("../pages/Deployment");
    render(wrap(<Deployment />));

    expect(await screen.findByRole("alert")).toHaveTextContent("uses a different mapping table");
  });

  it("answers a non-admin with a plain refusal", async () => {
    const { api } = await import("../api");
    vi.mocked(api.getDeployment).mockRejectedValue(new ApiError(403, "organisation admins only"));
    const { Deployment } = await import("../pages/Deployment");
    render(wrap(<Deployment />));

    expect(await screen.findByRole("alert")).toHaveTextContent("Organisation admins only.");
  });
});

describe("Deployment link in the header", () => {
  beforeEach(() => {
    meMock.mockReset();
    window.history.replaceState(null, "", "/");
  });

  it.each([
    ["admin", true],
    ["member", false],
  ])("is shown to an %s: %s", async (role, shown) => {
    meMock.mockResolvedValue({
      id: "usr_1",
      email: "op@acme.test",
      display_name: null,
      org_role: role,
      csrf_token: "c",
      auth: "session",
    });
    const { App } = await import("../app");
    render(wrap(<App />));
    await screen.findByText("API tokens");
    expect(screen.queryByRole("button", { name: "Deployment" }) !== null).toBe(shown);
  });
});
