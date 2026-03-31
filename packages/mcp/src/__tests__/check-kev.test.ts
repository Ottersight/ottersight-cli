import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@ottersight/scanner", () => {
  return {
    loadKev: vi.fn(),
  };
});

describe("handleCheckKev", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns inKev: true and mentions 'actively exploited' for known CVE", async () => {
    const { loadKev } = await import("@ottersight/scanner");
    vi.mocked(loadKev).mockResolvedValue(new Set(["CVE-2021-44228"]));

    const { handleCheckKev } = await import("../tools/check-kev.js");
    const result = await handleCheckKev({ cve_id: "CVE-2021-44228" });

    expect(result.structuredContent.inKev).toBe(true);
    expect(result.structuredContent.cveId).toBe("CVE-2021-44228");
    expect(result.content[0].type).toBe("text");
    expect((result.content[0] as { type: string; text: string }).text.toLowerCase()).toContain("actively exploited");
  });

  it("returns inKev: false and mentions 'NOT in CISA KEV' for unknown CVE", async () => {
    const { loadKev } = await import("@ottersight/scanner");
    vi.mocked(loadKev).mockResolvedValue(new Set(["CVE-2021-44228"]));

    const { handleCheckKev } = await import("../tools/check-kev.js");
    const result = await handleCheckKev({ cve_id: "CVE-2024-9999" });

    expect(result.structuredContent.inKev).toBe(false);
    expect(result.structuredContent.cveId).toBe("CVE-2024-9999");
    expect((result.content[0] as { type: string; text: string }).text).toContain("NOT in CISA KEV");
  });
});
