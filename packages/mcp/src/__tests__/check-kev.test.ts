import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ExploitedInfo } from "@ottersight/scanner";

vi.mock("@ottersight/scanner", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@ottersight/scanner")>();
  return { ...actual, loadExploited: vi.fn() };
});

const EXPLOITED = new Map<string, ExploitedInfo>([
  ["CVE-2021-44228", { sources: ["cisa_kev", "eukev_kev"], dateAdded: "2021-12-10", euvdId: "EUVD-2021-29270" }],
  ["CVE-2015-7501", { sources: ["eukev_kev"], dateAdded: "2025-07-14", euvdId: "EUVD-2022-3799" }],
]);

type Text = { type: string; text: string };

describe("handleCheckKev", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reports known exploitation with source, date and EUVD ID", async () => {
    const { loadExploited } = await import("@ottersight/scanner");
    vi.mocked(loadExploited).mockResolvedValue(EXPLOITED);

    const { handleCheckKev } = await import("../tools/check-kev.js");
    const result = await handleCheckKev({ cve_id: "CVE-2021-44228" });

    expect(result.structuredContent).toMatchObject({
      cveId: "CVE-2021-44228",
      inKev: true,
      exploitedSources: ["cisa_kev", "eukev_kev"],
      exploitedSince: "2021-12-10",
      euvdId: "EUVD-2021-29270",
    });
    expect((result.content[0] as Text).text).toContain("known exploited: listed in EU + CISA KEV since 2021-12-10");
  });

  it("detects EU-KEV-only CVEs that CISA KEV misses", async () => {
    const { loadExploited } = await import("@ottersight/scanner");
    vi.mocked(loadExploited).mockResolvedValue(EXPLOITED);

    const { handleCheckKev } = await import("../tools/check-kev.js");
    const result = await handleCheckKev({ cve_id: "CVE-2015-7501" });

    expect(result.structuredContent.exploitedSources).toEqual(["eukev_kev"]);
    expect((result.content[0] as Text).text).toContain("EU KEV");
  });

  it("returns inKev: false for unknown CVE", async () => {
    const { loadExploited } = await import("@ottersight/scanner");
    vi.mocked(loadExploited).mockResolvedValue(EXPLOITED);

    const { handleCheckKev } = await import("../tools/check-kev.js");
    const result = await handleCheckKev({ cve_id: "CVE-2024-9999" });

    expect(result.structuredContent.inKev).toBe(false);
    expect(result.structuredContent.exploitedSources).toEqual([]);
    expect((result.content[0] as Text).text).toContain("NOT in EU KEV or CISA KEV");
  });
});
