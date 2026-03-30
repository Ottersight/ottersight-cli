import { describe, it, expect, vi, beforeEach } from "vitest";

// kev.ts uses module-level cache (kevSet, kevLoadedAt).
// We reset modules before each test to get a fresh cache state.

describe("loadKev", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("returns Set of CVE IDs (mock fetch)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            { cveID: "CVE-2021-23337" },
            { cveID: "CVE-2024-1234" },
          ],
        }),
      })
    );

    const { loadKev } = await import("../kev.js");
    const result = await loadKev();

    expect(result).toBeInstanceOf(Set);
    expect(result.size).toBe(2);
    expect(result.has("CVE-2021-23337")).toBe(true);
    expect(result.has("CVE-2024-1234")).toBe(true);

    vi.unstubAllGlobals();
  });

  it("returns cached result on second call (fetch called only once)", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerabilities: [{ cveID: "CVE-2021-23337" }],
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const { loadKev } = await import("../kev.js");
    await loadKev();
    await loadKev();

    expect(mockFetch).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
  });

  it("returns empty Set on network failure (graceful degrade)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network error"))
    );

    const { loadKev } = await import("../kev.js");
    const result = await loadKev();

    expect(result).toBeInstanceOf(Set);
    expect(result.size).toBe(0);

    vi.unstubAllGlobals();
  });
});
