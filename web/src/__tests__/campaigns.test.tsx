import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Campaign, CampaignDiff } from "../api";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listCampaigns: vi.fn(),
      listTargets: vi.fn(async () => [{ id: "tgt_1", type: "llm_endpoint", spec: { host: "gw.acme.test" } }]),
      createCampaign: vi.fn(),
      getCampaign: vi.fn(),
      updateCampaign: vi.fn(),
      listCampaignRuns: vi.fn(async () => []),
      listCampaignDiffs: vi.fn(),
      listAlerts: vi.fn(),
    },
  };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

const CAMPAIGN: Campaign = {
  id: "cmp_1",
  engagement_id: "eng_1",
  name: "weekly injection",
  adapter: "echo",
  target_id: "tgt_1",
  params: {},
  interval_minutes: 60,
  enabled: true,
  next_run_at: "2026-10-03T12:00:00Z",
  created_at: "2026-10-03T11:00:00Z",
};

const entry = (rule: string, title: string) => ({
  fingerprint: `sha256:${rule}`,
  finding_id: `fnd_${rule}`,
  rule_id: rule,
  severity: "high",
  title,
});

const DIFFS: CampaignDiff[] = [
  {
    id: "dif_2",
    campaign_id: "cmp_1",
    run_id: "run_2",
    previous_run_id: "run_1",
    baseline: false,
    new: [entry("garak.c", '<img src=x onerror="alert(1)">')],
    regressed: [entry("garak.b", "came back")],
    resolved: [],
    unchanged_count: 1,
    findings_count: 3,
    worsened: true,
    created_at: "2026-10-03T11:30:00Z",
  },
  {
    id: "dif_1",
    campaign_id: "cmp_1",
    run_id: "run_1",
    previous_run_id: null,
    baseline: true,
    new: [],
    regressed: [],
    resolved: [],
    unchanged_count: 0,
    findings_count: 2,
    worsened: false,
    created_at: "2026-10-03T11:00:00Z",
  },
];

describe("Campaigns panel (spec 018)", () => {
  it("lists campaigns and creates one", async () => {
    const { api } = await import("../api");
    vi.mocked(api.listCampaigns).mockResolvedValue([CAMPAIGN]);
    vi.mocked(api.createCampaign).mockResolvedValueOnce({ ...CAMPAIGN, id: "cmp_2", name: "nightly" });
    const { CampaignsPanel } = await import("../components/CampaignsPanel");
    render(wrap(<CampaignsPanel engagementId="eng_1" />));

    expect(await screen.findByText("weekly injection")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("campaign name"), { target: { value: "nightly" } });
    await screen.findByRole("option", { name: "llm_endpoint: gw.acme.test" });
    fireEvent.change(screen.getByLabelText("campaign target"), { target: { value: "tgt_1" } });
    fireEvent.change(screen.getByLabelText("interval minutes"), { target: { value: "120" } });
    fireEvent.click(screen.getByRole("button", { name: "New campaign" }));
    await waitFor(() =>
      expect(api.createCampaign).toHaveBeenCalledWith("eng_1", {
        name: "nightly",
        adapter: "echo",
        target_id: "tgt_1",
        interval_minutes: 120,
      }),
    );
  });

  it("shows the API's refusal", async () => {
    const { api, ApiError } = await import("../api");
    vi.mocked(api.listCampaigns).mockResolvedValue([]);
    vi.mocked(api.createCampaign).mockRejectedValueOnce(new ApiError(422, "interval_minutes must be at least 60"));
    const { CampaignsPanel } = await import("../components/CampaignsPanel");
    render(wrap(<CampaignsPanel engagementId="eng_1" />));

    await screen.findByText("No campaigns yet.");
    fireEvent.change(screen.getByLabelText("campaign name"), { target: { value: "too often" } });
    await screen.findByRole("option", { name: "llm_endpoint: gw.acme.test" });
    fireEvent.change(screen.getByLabelText("campaign target"), { target: { value: "tgt_1" } });
    fireEvent.change(screen.getByLabelText("interval minutes"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: "New campaign" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("interval_minutes must be at least 60");
  });
});

describe("Campaign page (spec 018)", () => {
  it("shows diffs with counts and escaped entries, and alerts", async () => {
    const { api } = await import("../api");
    vi.mocked(api.getCampaign).mockResolvedValue(CAMPAIGN);
    vi.mocked(api.listCampaignDiffs).mockResolvedValue(DIFFS);
    vi.mocked(api.listAlerts).mockResolvedValue([
      {
        id: "alr_1",
        campaign_id: "cmp_1",
        diff_id: "dif_2",
        state: "sent",
        attempts: 1,
        last_error: null,
        created_at: "2026-10-03T11:30:01Z",
        sent_at: "2026-10-03T11:30:02Z",
      },
      {
        id: "alr_other",
        campaign_id: "cmp_other",
        diff_id: "dif_9",
        state: "failed",
        attempts: 5,
        last_error: "HTTP 500",
        created_at: "2026-10-03T11:30:01Z",
        sent_at: null,
      },
    ]);
    const { Campaign } = await import("../pages/Campaign");
    const { container } = render(wrap(<Campaign engagementId="eng_1" campaignId="cmp_1" />));

    const rows = await screen.findAllByTestId("diff-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("worsened");
    expect(rows[0]).toHaveTextContent("1 new · 1 regressed · 0 resolved · 1 unchanged");
    expect(rows[0]).toHaveTextContent('garak.c — <img src=x onerror="alert(1)">');
    expect(container.querySelector("img")).toBeNull(); // rendered as text
    expect(rows[1]).toHaveTextContent("baseline");
    expect(rows[1]).toHaveTextContent("2 finding(s)");
    const alerts = await screen.findAllByTestId("alert-row");
    expect(alerts).toHaveLength(1); // only this campaign's
    expect(alerts[0]).toHaveTextContent("sent");
  });

  it("pauses a campaign", async () => {
    const { api } = await import("../api");
    vi.mocked(api.getCampaign).mockResolvedValue(CAMPAIGN);
    vi.mocked(api.listCampaignDiffs).mockResolvedValue([]);
    vi.mocked(api.listAlerts).mockResolvedValue([]);
    vi.mocked(api.updateCampaign).mockResolvedValueOnce({ ...CAMPAIGN, enabled: false });
    const { Campaign } = await import("../pages/Campaign");
    render(wrap(<Campaign engagementId="eng_1" campaignId="cmp_1" />));

    fireEvent.click(await screen.findByRole("button", { name: "Pause" }));
    await waitFor(() => expect(api.updateCampaign).toHaveBeenCalledWith("eng_1", "cmp_1", { enabled: false }));
  });

  it("hides alerts from a viewer instead of erroring", async () => {
    const { api, ApiError } = await import("../api");
    vi.mocked(api.getCampaign).mockResolvedValue(CAMPAIGN);
    vi.mocked(api.listCampaignDiffs).mockResolvedValue([]);
    vi.mocked(api.listAlerts).mockRejectedValue(new ApiError(403, "requires one of: owner, operator, analyst"));
    const { Campaign } = await import("../pages/Campaign");
    render(wrap(<Campaign engagementId="eng_1" campaignId="cmp_1" />));

    await screen.findByText("No successful run yet.");
    await waitFor(() => expect(screen.queryByText("Alerts")).toBeNull());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
