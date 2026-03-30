import { describe, it, expect, vi, beforeEach } from "vitest";
import { lookupLatestVersions } from "../registries.js";
import type { ComponentInput } from "../types.js";

describe("lookupLatestVersions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns version map for npm components (mock fetch)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ version: "4.17.21" }),
      })
    );

    const comps: ComponentInput[] = [
      { id: "comp-1", name: "lodash", version: "4.17.20", ecosystem: "npm" },
    ];
    const result = await lookupLatestVersions(comps);

    expect(result.size).toBe(1);
    const entry = result.get("comp-1");
    expect(entry?.latestVersion).toBe("4.17.21");
    expect(entry?.isOutdated).toBe(true);

    vi.unstubAllGlobals();
  });

  it("handles scoped npm packages (e.g. @scope/name)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        // @ottersight/scanner → registry.npmjs.org/@ottersight%2Fscanner/latest
        // The code only encodes the slash, not the @ sign
        if (url.includes("@ottersight%2Fscanner")) {
          return {
            ok: true,
            json: async () => ({ version: "1.2.3" }),
          };
        }
        return { ok: false };
      })
    );

    const comps: ComponentInput[] = [
      { id: "comp-scoped", name: "@ottersight/scanner", version: "1.0.0", ecosystem: "npm" },
    ];
    const result = await lookupLatestVersions(comps);

    expect(result.size).toBe(1);
    const entry = result.get("comp-scoped");
    expect(entry?.latestVersion).toBe("1.2.3");
    expect(entry?.isOutdated).toBe(true);

    vi.unstubAllGlobals();
  });

  it("returns empty map for unsupported ecosystem", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const comps: ComponentInput[] = [
      { id: "comp-unknown", name: "some-pkg", version: "1.0.0", ecosystem: "maven" },
    ];
    const result = await lookupLatestVersions(comps);

    expect(result.size).toBe(0);
    // fetch should not be called for unsupported ecosystems
    expect(mockFetch).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it("marks isOutdated correctly when versions differ", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ version: "5.0.0" }),
      })
    );

    const comps: ComponentInput[] = [
      { id: "comp-outdated", name: "react", version: "4.0.0", ecosystem: "npm" },
      { id: "comp-uptodate", name: "vue", version: "5.0.0", ecosystem: "npm" },
    ];
    const result = await lookupLatestVersions(comps);

    expect(result.get("comp-outdated")?.isOutdated).toBe(true);
    expect(result.get("comp-uptodate")?.isOutdated).toBe(false);

    vi.unstubAllGlobals();
  });
});
