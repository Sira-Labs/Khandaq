import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Run } from "../api";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, listRuns: vi.fn() } };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

const base: Run = {
  id: "run_1",
  adapter: "garak",
  state: "queued",
  reject_reason: null,
  target_id: "tgt_1",
  created_at: "2026-10-03T10:00:00Z",
  started_at: null,
  ended_at: null,
};

describe("Runs panel (spec 015)", () => {
  it("shows state badges, duration and an escaped failure reason", async () => {
    const { api } = await import("../api");
    vi.mocked(api.listRuns).mockResolvedValueOnce([
      { ...base, id: "run_q" },
      {
        ...base,
        id: "run_f",
        state: "failed",
        started_at: "2026-10-03T10:00:00Z",
        ended_at: "2026-10-03T10:01:05Z",
        reject_reason: "adapter failed: <img src=x onerror=alert(1)>",
      },
      { ...base, id: "run_r", adapter: "echo", state: "rejected", reject_reason: "host not in scope" },
    ]);
    const { RunsPanel } = await import("../components/RunsPanel");
    const { container } = render(wrap(<RunsPanel engagementId="eng_1" />));

    expect(await screen.findAllByTestId("run-row")).toHaveLength(3);
    expect(screen.getByText("queued")).toBeInTheDocument();
    expect(screen.getByText("1m 5s")).toBeInTheDocument();
    expect(screen.getByText("adapter failed: <img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull(); // rendered as text, not markup
    expect(screen.getByText("host not in scope")).toBeInTheDocument();
  });

  it("polls only while a run can still change state", async () => {
    const { runPollInterval, RUN_POLL_MS } = await import("../components/RunsPanel");
    expect(runPollInterval(undefined)).toBe(false);
    expect(runPollInterval([{ ...base, state: "succeeded" }, { ...base, state: "failed" }])).toBe(false);
    expect(runPollInterval([{ ...base, state: "succeeded" }, { ...base, state: "running" }])).toBe(RUN_POLL_MS);
    expect(runPollInterval([{ ...base, state: "queued" }])).toBe(RUN_POLL_MS);
  });

  it("refetches while a run is active, refreshes ledger and findings when it ends, then stops", async () => {
    // Only the polling interval is faked: React and React Query's own zero-delay notifications
    // keep running on real timers, so the rendered list updates as it would in a browser.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const { api } = await import("../api");
      const listRuns = vi.mocked(api.listRuns);
      listRuns.mockReset();
      listRuns.mockResolvedValueOnce([{ ...base, state: "running", started_at: "2026-10-03T10:00:00Z" }]);
      listRuns.mockResolvedValue([
        { ...base, state: "succeeded", started_at: "2026-10-03T10:00:00Z", ended_at: "2026-10-03T10:00:09Z" },
      ]);
      const { RunsPanel, RUN_POLL_MS } = await import("../components/RunsPanel");
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      const invalidate = vi.spyOn(qc, "invalidateQueries");
      render(
        <QueryClientProvider client={qc}>
          <RunsPanel engagementId="eng_1" />
        </QueryClientProvider>,
      );

      expect(await screen.findByText("running")).toBeInTheDocument();
      expect(listRuns).toHaveBeenCalledTimes(1);
      expect(invalidate).not.toHaveBeenCalled();

      // Still running: the list refetches after one interval and the run is now final.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(RUN_POLL_MS);
      });
      expect(await screen.findByText("succeeded")).toBeInTheDocument();
      expect(listRuns).toHaveBeenCalledTimes(2);
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ["ledger", "eng_1"] });
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ["findings", "eng_1"] });

      // Nothing can change any more: no further requests, however long the page stays open.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(RUN_POLL_MS * 4);
      });
      expect(listRuns).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("formats durations and leaves unfinished runs without one", async () => {
    const { formatDuration } = await import("../components/RunsPanel");
    expect(formatDuration(base)).toBeNull();
    expect(
      formatDuration({ ...base, started_at: "2026-10-03T10:00:00Z", ended_at: "2026-10-03T10:00:42Z" }),
    ).toBe("42s");
  });
});
