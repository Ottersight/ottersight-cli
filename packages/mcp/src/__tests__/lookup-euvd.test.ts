import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@ottersight/scanner", () => {
  return {
    loadEuvdMapping: vi.fn(),
  };
});

describe("handleLookupEuvd", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns euvdId and mentions EUVD ID in Markdown for known CVE", async () => {
    const { loadEuvdMapping } = await import("@ottersight/scanner");
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-23337", "EUVD-2021-23337"]]));

    const { handleLookupEuvd } = await import("../tools/lookup-euvd.js");
    const result = await handleLookupEuvd({ cve_id: "CVE-2021-23337" });

    expect(result.structuredContent.euvdId).toBe("EUVD-2021-23337");
    expect(result.structuredContent.cveId).toBe("CVE-2021-23337");
    expect(result.content[0].type).toBe("text");
    expect((result.content[0] as { type: string; text: string }).text).toContain("EUVD-2021-23337");
  });

  it("returns euvdId: null and 'No EUVD entry found' for unknown CVE", async () => {
    const { loadEuvdMapping } = await import("@ottersight/scanner");
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-23337", "EUVD-2021-23337"]]));

    const { handleLookupEuvd } = await import("../tools/lookup-euvd.js");
    const result = await handleLookupEuvd({ cve_id: "CVE-2024-9999" });

    expect(result.structuredContent.euvdId).toBeNull();
    expect(result.structuredContent.cveId).toBe("CVE-2024-9999");
    expect((result.content[0] as { type: string; text: string }).text).toContain("No EUVD entry found");
  });
});
