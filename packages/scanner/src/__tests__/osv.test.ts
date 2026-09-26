import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { GrypeMatch } from "../types.js";

function match(id: string, related: string[] = []): GrypeMatch {
  return {
    vulnerability: { id, severity: "high" },
    artifact: { name: "pkg", version: "1.0.0" },
    relatedVulnerabilities: related.map((r) => ({ id: r, severity: "high" })),
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("loadCveAliases", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.resetModules(); // module-level cache
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("queries OSV only for GHSA findings without a CVE, once per ID", async () => {
    fetchMock.mockResolvedValue(json({ id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2024-0001"] }));
    const { loadCveAliases } = await import("../osv.js");

    const result = await loadCveAliases([
      match("CVE-2021-23337"),
      match("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]),
      match("GHSA-aaaa-bbbb-cccc"),
      match("GHSA-aaaa-bbbb-cccc"),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc");
    expect(fetchMock.mock.calls[0][1].headers["User-Agent"]).toMatch(/^OtterSight/);
    expect(result.get("GHSA-aaaa-bbbb-cccc")).toEqual(["CVE-2024-0001"]);
  });

  it("keeps only CVE aliases, in OSV order", async () => {
    fetchMock.mockResolvedValue(json({ aliases: ["CVE-2021-1", "GHSA-zzzz-zzzz-zzzz", "CVE-2026-2", 42] }));
    const { loadCveAliases } = await import("../osv.js");
    const result = await loadCveAliases([match("GHSA-aaaa-bbbb-cccc")]);
    expect(result.get("GHSA-aaaa-bbbb-cccc")).toEqual(["CVE-2021-1", "CVE-2026-2"]);
  });

  it("404 = no CVE, cached; 24 h cache avoids a second request", async () => {
    fetchMock.mockResolvedValue(json({ code: 5, message: "Bug not found." }, 404));
    const { loadCveAliases } = await import("../osv.js");
    expect((await loadCveAliases([match("GHSA-aaaa-bbbb-cccc")])).get("GHSA-aaaa-bbbb-cccc")).toEqual([]);
    await loadCveAliases([match("GHSA-aaaa-bbbb-cccc")]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("never throws: network error, 5xx, HTML body are skipped and not cached", async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValueOnce(new Response("oops", { status: 503 }))
      .mockResolvedValueOnce(new Response("<html>", { status: 200, headers: { "content-type": "text/html" } }));
    const { loadCveAliases } = await import("../osv.js");

    const result = await loadCveAliases([
      match("GHSA-aaaa-aaaa-aaaa"),
      match("GHSA-bbbb-bbbb-bbbb"),
      match("GHSA-cccc-cccc-cccc"),
    ]);
    expect(result.size).toBe(0);

    fetchMock.mockResolvedValue(json({ aliases: ["CVE-2024-0001"] }));
    expect((await loadCveAliases([match("GHSA-aaaa-aaaa-aaaa")])).get("GHSA-aaaa-aaaa-aaaa")).toEqual(["CVE-2024-0001"]);
  });

  it("runs at most 8 requests in parallel", async () => {
    let inFlight = 0;
    let peak = 0;
    fetchMock.mockImplementation(async () => {
      peak = Math.max(peak, ++inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return json({ aliases: [] });
    });
    const { loadCveAliases } = await import("../osv.js");
    const ids = Array.from({ length: 20 }, (_, i) => match(`GHSA-${String(i).padStart(4, "0")}-xxxx-xxxx`));
    const result = await loadCveAliases(ids);
    expect(result.size).toBe(20);
    expect(peak).toBe(8);
  });

  it("does nothing when no finding needs a CVE", async () => {
    const { loadCveAliases } = await import("../osv.js");
    expect((await loadCveAliases([match("CVE-2021-23337")])).size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("loadCveAliases with a mirror alias map", () => {
  const MAP_URL = "https://mirror.example.eu/osv/ghsa-cve.json";
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.resetModules();
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("downloads the map once and resolves locally, never contacting OSV.dev", async () => {
    fetchMock.mockResolvedValue(json({ "GHSA-aaaa-bbbb-cccc": ["CVE-2024-0001", "OSV-2024-1"] }));
    const { loadCveAliases } = await import("../osv.js");
    const matches = [match("GHSA-aaaa-bbbb-cccc"), match("GHSA-dddd-eeee-ffff")];

    const first = await loadCveAliases(matches, { aliasMapUrl: MAP_URL });
    const second = await loadCveAliases(matches, { aliasMapUrl: MAP_URL });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(MAP_URL);
    expect(first.get("GHSA-aaaa-bbbb-cccc")).toEqual(["CVE-2024-0001"]);
    expect(first.get("GHSA-dddd-eeee-ffff")).toEqual([]); // not in the map = no CVE
    expect(second).toEqual(first);
  });

  it("skips the download when no finding needs a CVE", async () => {
    const { loadCveAliases } = await import("../osv.js");
    const result = await loadCveAliases([match("CVE-2021-23337")], { aliasMapUrl: MAP_URL });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.size).toBe(0);
  });

  it("returns an empty map when the mirror fails (never throws, no OSV fallback)", async () => {
    fetchMock.mockResolvedValue(new Response("nope", { status: 503 }));
    const { loadCveAliases } = await import("../osv.js");
    const result = await loadCveAliases([match("GHSA-aaaa-bbbb-cccc")], { aliasMapUrl: MAP_URL });
    expect(result.size).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(MAP_URL);
  });
});
