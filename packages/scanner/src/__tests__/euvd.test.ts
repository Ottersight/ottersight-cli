import { describe, it, expect, vi, beforeEach } from "vitest";

// euvd.ts uses module-level cache (euvdMap, euvdLoadedAt).
// We reset modules before each test to get fresh cache state.

const MOCK_CSV = `euvd_id,cve_id
EUVD-2021-0001,CVE-2021-23337
EUVD-2024-0002,CVE-2024-1234
`;

describe("loadEuvdMapping", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("returns Map from CVE to EUVD-ID (mock fetch)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        text: async () => MOCK_CSV,
      })
    );

    const { loadEuvdMapping } = await import("../euvd.js");
    const result = await loadEuvdMapping();

    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(2);
    expect(result.get("CVE-2021-23337")).toBe("EUVD-2021-0001");
    expect(result.get("CVE-2024-1234")).toBe("EUVD-2024-0002");

    vi.unstubAllGlobals();
  });

  it("parses CSV correctly skipping header", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        text: async () => MOCK_CSV,
      })
    );

    const { loadEuvdMapping } = await import("../euvd.js");
    const result = await loadEuvdMapping();

    // Header line "euvd_id,cve_id" must not appear as a key
    expect(result.has("cve_id")).toBe(false);
    expect(result.has("euvd_id")).toBe(false);
    expect(result.size).toBe(2);

    vi.unstubAllGlobals();
  });

  it("returns empty Map on network failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network error"))
    );

    const { loadEuvdMapping } = await import("../euvd.js");
    const result = await loadEuvdMapping();

    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(0);

    vi.unstubAllGlobals();
  });
});
