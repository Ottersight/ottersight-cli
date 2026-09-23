import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@ottersight/scanner", () => {
  return {
    loadEuvdMapping: vi.fn(),
    lookupEuvdRecord: vi.fn().mockResolvedValue(null),
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

  it("includes EUVD record details (CVSS, EPSS, exploitation, aliases) when available", async () => {
    const { loadEuvdMapping, lookupEuvdRecord } = await import("@ottersight/scanner");
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2015-7501", "EUVD-2022-3799"]]));
    vi.mocked(lookupEuvdRecord).mockResolvedValue({
      id: "EUVD-2022-3799",
      description: "Deserialization of untrusted data in Apache Commons Collections.",
      datePublished: "2017-11-09",
      dateUpdated: "2026-09-20",
      exploitedSince: "2025-07-14",
      baseScore: 9.8,
      baseScoreVersion: "3.1",
      baseScoreVector: null,
      epss: 0.70081,
      aliases: ["CVE-2015-7501", "GHSA-fjq5-5j5f-mvxh"],
      references: [],
      assigner: "redhat",
    });

    const { handleLookupEuvd } = await import("../tools/lookup-euvd.js");
    const result = await handleLookupEuvd({ cve_id: "CVE-2015-7501" });
    const text = (result.content[0] as { type: string; text: string }).text;

    expect(result.structuredContent.record?.epss).toBe(0.70081);
    expect(text).toContain("CVSS 3.1 9.8 (assigned by redhat)");
    expect(text).toContain("EPSS: 70.1%");
    expect(text).toContain("Known exploited since 2025-07-14");
    expect(text).toContain("Source: ENISA EU Vulnerability Database (EUVD).");
  });
});
