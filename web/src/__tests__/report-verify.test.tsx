import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ReportVerify } from "../api";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, verifyReport: vi.fn(), downloadReport: vi.fn() } };
});

const ROOT = "sha256:" + "a".repeat(64);
const report = (engagementId = "eng_1", evidence: unknown = { root: ROOT, count: 3, verify: { ok: true } }) =>
  JSON.stringify({ engagement: { id: engagementId }, evidence, findings: [] });

function upload(text: string) {
  const input = screen.getByLabelText("report file") as HTMLInputElement;
  const file = new File([text], "report.json", { type: "application/json" });
  Object.defineProperty(file, "text", { value: async () => text });
  fireEvent.change(input, { target: { files: [file] } });
}

const intact: ReportVerify = {
  ok: true,
  pinned: { root: ROOT, count: 3 },
  current: { root: ROOT, count: 5 },
  appended_since: 2,
  issued: true,
  verify: { ok: true, count: 5 },
};

describe("Report re-verification (spec 015)", () => {
  it("shows an intact verdict with what was appended and whether it was issued here", async () => {
    const { api } = await import("../api");
    vi.mocked(api.verifyReport).mockResolvedValueOnce(intact);
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    upload(report());
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Evidence intact ✓ — 2 entries appended since");
    expect(status).toHaveTextContent("Issued by this instance.");
    expect(api.verifyReport).toHaveBeenCalledWith("eng_1", { root: ROOT, count: 3, verify: { ok: true } });
  });

  it("shows a broken verdict with the sequence and reason", async () => {
    const { api } = await import("../api");
    vi.mocked(api.verifyReport).mockResolvedValueOnce({
      ...intact,
      ok: false,
      appended_since: null,
      issued: false,
      verify: { ok: false, count: 2, broken_at: 3, reason: "the chain is shorter than the pinned count (entries were removed)" },
    });
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    upload(report());
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Evidence broken at #3: the chain is shorter than the pinned count");
    expect(status).toHaveTextContent("No export of this report on record here.");
  });

  it("explains that a pre-013 report cannot be verified", async () => {
    const { api, ApiError } = await import("../api");
    vi.mocked(api.verifyReport).mockRejectedValueOnce(new ApiError(422, "count: Field required"));
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    upload(report("eng_1", { root: ROOT, verify: { ok: true } }));
    expect(await screen.findByRole("alert")).toHaveTextContent("has no ledger entry count");
  });

  it("refuses a file that is not a report before any request", async () => {
    const { api } = await import("../api");
    vi.mocked(api.verifyReport).mockClear();
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    upload("not json at all");
    expect(await screen.findByRole("alert")).toHaveTextContent("not a Khandaq report export");
    upload(JSON.stringify({ findings: [] }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("not a Khandaq report export"));
    expect(api.verifyReport).not.toHaveBeenCalled();
  });

  it("points out a report that names another engagement", async () => {
    const { api } = await import("../api");
    vi.mocked(api.verifyReport).mockResolvedValueOnce(intact);
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    upload(report("eng_other"));
    expect(await screen.findByRole("status")).toHaveTextContent("This report names engagement eng_other");
  });

  it("downloads the report as a file", async () => {
    const { api } = await import("../api");
    vi.mocked(api.downloadReport).mockResolvedValueOnce({ blob: new Blob(["{}"]), filename: "khandaq-report-eng_1.json" });
    URL.createObjectURL = vi.fn(() => "blob:mock");
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { ReportPanel } = await import("../components/ReportPanel");
    render(<ReportPanel engagementId="eng_1" />);

    fireEvent.click(screen.getByRole("button", { name: "Download JSON" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(api.downloadReport).toHaveBeenCalledWith("eng_1", "json");
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock");
  });
});
