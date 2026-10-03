import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, downloadEvidence: vi.fn() } };
});

describe("Evidence download (spec 015)", () => {
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => "blob:mock");
    URL.revokeObjectURL = vi.fn();
  });
  afterEach(() => vi.restoreAllMocks());

  it("saves the bytes under the server's file name and revokes the URL", async () => {
    const { api } = await import("../api");
    vi.mocked(api.downloadEvidence).mockResolvedValueOnce({
      blob: new Blob(["raw"]),
      filename: "ev_1-garak.report.jsonl",
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { EvidenceList } = await import("../components/EvidenceList");
    render(<EvidenceList engagementId="eng_1" evidenceIds={["ev_1"]} />);

    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(api.downloadEvidence).toHaveBeenCalledWith("eng_1", "ev_1");
    expect(URL.createObjectURL).toHaveBeenCalled();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it.each([
    [403, "Your role cannot download raw evidence"],
    [404, "No stored content for this evidence."],
    [409, "Integrity check failed"],
    [500, "boom"],
  ])("explains a %i", async (status, text) => {
    const { api, ApiError } = await import("../api");
    vi.mocked(api.downloadEvidence).mockRejectedValueOnce(new ApiError(status, "boom"));
    const { EvidenceList } = await import("../components/EvidenceList");
    render(<EvidenceList engagementId="eng_1" evidenceIds={["ev_1"]} />);

    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(text);
  });

  it("says when a finding has no evidence", async () => {
    const { EvidenceList } = await import("../components/EvidenceList");
    render(<EvidenceList engagementId="eng_1" evidenceIds={[]} />);
    expect(screen.getByText("none")).toBeInTheDocument();
  });
});
