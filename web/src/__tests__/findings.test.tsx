import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Finding } from "../api";

const FINDINGS: Finding[] = [
  {
    id: "fnd_1",
    fingerprint: "sha256:a",
    rule_id: "echo.inject.a",
    // Untrusted text: must render as text, never as HTML.
    title: '<img src=x onerror="alert(1)">',
    severity: "high",
    status: "open",
    phase: "04-prompt-injection",
    mappings: [{ framework: "owasp-llm-2026", id: "LLM01" }],
    evidence: ["ev_1", "ev_2"],
    also_found_by: ["pyrit"],
  },
  {
    id: "fnd_2",
    fingerprint: "sha256:b",
    rule_id: "echo.leak",
    title: "info leak",
    severity: "low",
    status: "open",
    phase: "03-scanning",
    mappings: [{ framework: "owasp-llm-2026", id: "LLM02" }],
    evidence: ["ev_3"],
    also_found_by: [],
  },
];

vi.mock("../api", async (orig) => {
  const actual = await orig<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, listFindings: vi.fn(async () => FINDINGS) },
  };
});

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

describe("Findings inbox", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders deduped findings and escapes untrusted titles", async () => {
    const { Findings } = await import("../pages/Findings");
    const { container } = render(wrap(<Findings engagementId="eng_1" />));

    // The malicious title is shown as literal text, and no <img> element is injected.
    await waitFor(() => expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument());
    expect(container.querySelector("img")).toBeNull();

    expect(screen.getByText("LLM01")).toBeInTheDocument();
    expect(screen.getByText("+1 tools")).toBeInTheDocument();
  });

  it("shows a severity filter", async () => {
    const { Findings } = await import("../pages/Findings");
    render(wrap(<Findings engagementId="eng_1" />));
    expect(await screen.findByLabelText("severity filter")).toBeInTheDocument();
  });
});
