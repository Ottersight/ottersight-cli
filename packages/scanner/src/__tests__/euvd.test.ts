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

// Trimmed excerpt of https://euvdservices.enisa.europa.eu/api/kev/dump (2026-09-23)
const KEV_DUMP = [
  { cveId: "CVE-2021-22555", euvdId: "EUVD-2021-9696", dateAdded: "2025-10-06", sources: ["cisa_kev"] },
  { cveId: "CVE-2015-7501", euvdId: "EUVD-2022-3799", dateAdded: "2025-07-14", sources: ["eukev_kev"] },
  { cveId: "CVE-2021-44228", euvdId: "EUVD-2021-29270", dateAdded: "2021-12-10", sources: ["cisa_kev", "eukev_kev"] },
  { euvdId: "EUVD-2026-0000", dateAdded: "2026-01-01", sources: ["eukev_kev"] }, // no cveId → skipped
  { cveId: "CVE-2026-0001", dateAdded: "2026-01-01", sources: ["unknown_source"] }, // unknown source → skipped
];

const CISA_KEV = { vulnerabilities: [{ cveID: "CVE-2021-22555" }] };

// The real dump has ~1,700 entries; loadExploited() rejects dumps under 1,000 as truncated.
const FILLER = Array.from({ length: 1000 }, (_, i) => ({
  cveId: `CVE-2000-${10000 + i}`,
  euvdId: `EUVD-2000-${i}`,
  dateAdded: "2022-01-01",
  sources: ["cisa_kev"],
}));
const FULL_DUMP = [...KEV_DUMP, ...FILLER];
const jsonHeaders = { get: (h: string) => (h.toLowerCase() === "content-type" ? "application/json" : null) };

describe("loadExploited", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("parses the EUVD KEV dump incl. EU-KEV-only entries", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => FULL_DUMP });
    vi.stubGlobal("fetch", fetchMock);

    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(fetchMock.mock.calls[0][0]).toBe("https://euvdservices.enisa.europa.eu/api/kev/dump");
    expect(result.size).toBe(3 + FILLER.length);
    expect(result.get("CVE-2015-7501")).toEqual({
      sources: ["eukev_kev"],
      dateAdded: "2025-07-14",
      euvdId: "EUVD-2022-3799",
    });
    expect(result.get("CVE-2021-44228")?.sources).toEqual(["cisa_kev", "eukev_kev"]);

    vi.unstubAllGlobals();
  });

  it("falls back to the CISA KEV mirror when EUVD fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("euvdservices")
          ? { ok: false, status: 503 }
          : { ok: true, json: async () => CISA_KEV },
      ),
    );

    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(result.size).toBe(1);
    expect(result.get("CVE-2021-22555")).toEqual({ sources: ["cisa_kev"], dateAdded: null, euvdId: null });

    vi.unstubAllGlobals();
  });

  it("returns an empty map when EUVD and CISA both fail (never throws)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(result.size).toBe(0);

    vi.unstubAllGlobals();
  });

  it("treats a non-array response as a failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("euvdservices")
          ? { ok: true, json: async () => ({ error: "maintenance" }) }
          : { ok: true, json: async () => CISA_KEV },
      ),
    );

    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(result.get("CVE-2021-22555")?.sources).toEqual(["cisa_kev"]);

    vi.unstubAllGlobals();
  });

  it("caches the EUVD dump for subsequent calls", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => FULL_DUMP });
    vi.stubGlobal("fetch", fetchMock);

    const { loadExploited } = await import("../euvd.js");
    await loadExploited();
    await loadExploited();

    const euvdCalls = fetchMock.mock.calls.filter(([url]) => String(url).includes("euvdservices"));
    expect(euvdCalls).toHaveLength(1);

    vi.unstubAllGlobals();
  });
});

describe("parseEuvdDate", () => {
  it("parses EUVD's US-locale timestamps as UTC dates", async () => {
    const { parseEuvdDate } = await import("../euvd.js");
    expect(parseEuvdDate("Sep 9, 2026, 1:00:31 PM")).toBe("2026-09-09");
    // Midnight must not shift to the previous day in timezones east of UTC
    expect(parseEuvdDate("Sep 22, 2026, 12:00:00 AM")).toBe("2026-09-22");
    expect(parseEuvdDate("Feb 14, 2025, 11:59:59 PM")).toBe("2025-02-14");
  });

  it("returns null for empty or invalid input", async () => {
    const { parseEuvdDate } = await import("../euvd.js");
    expect(parseEuvdDate("")).toBeNull();
    expect(parseEuvdDate(null)).toBeNull();
    expect(parseEuvdDate("garbage")).toBeNull();
  });
});

describe("splitEuvdList", () => {
  it("splits newline-separated aliases with a trailing newline", async () => {
    const { splitEuvdList } = await import("../euvd.js");
    expect(splitEuvdList("GHSA-3fvr-5gg9-225m\nCVE-2026-85102\n")).toEqual(["GHSA-3fvr-5gg9-225m", "CVE-2026-85102"]);
    expect(splitEuvdList("")).toEqual([]);
    expect(splitEuvdList(undefined)).toEqual([]);
  });
});

describe("lookupEuvdRecord", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  const RAW = {
    id: "EUVD-2026-75009",
    description: "Improper certificate trust validation …",
    datePublished: "Sep 9, 2026, 1:00:31 PM",
    dateUpdated: "Sep 23, 2026, 3:55:34 AM",
    exploitedSince: "Sep 22, 2026, 12:00:00 AM",
    baseScore: 9.8,
    baseScoreVersion: "3.1",
    baseScoreVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    references: "https://support.checkpoint.com/results/sk/sk1000117\n",
    aliases: "GHSA-3fvr-5gg9-225m\nCVE-2026-85102\n",
    assigner: "checkpoint",
    epss: 98.62,
  };

  it("normalises dates, lists and EPSS (×100 → 0–1)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify(RAW) }));
    const { lookupEuvdRecord } = await import("../euvd.js");
    const r = await lookupEuvdRecord("EUVD-2026-75009");

    expect(r).toMatchObject({
      id: "EUVD-2026-75009",
      datePublished: "2026-09-09",
      exploitedSince: "2026-09-22",
      baseScore: 9.8,
      epss: 0.9862,
      aliases: ["GHSA-3fvr-5gg9-225m", "CVE-2026-85102"],
      references: ["https://support.checkpoint.com/results/sk/sk1000117"],
    });
    vi.unstubAllGlobals();
  });

  it("returns null on 204 (unknown ID, empty body)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 204, text: async () => "" }));
    const { lookupEuvdRecord } = await import("../euvd.js");
    expect(await lookupEuvdRecord("EUVD-0000-0")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("returns null on network errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    const { lookupEuvdRecord } = await import("../euvd.js");
    expect(await lookupEuvdRecord("EUVD-2026-75009")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("maps a 0.0 base score to null (unscored)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ ...RAW, baseScore: 0 }) }));
    const { lookupEuvdRecord } = await import("../euvd.js");
    expect((await lookupEuvdRecord("EUVD-2026-75009"))?.baseScore).toBeNull();
    vi.unstubAllGlobals();
  });
});

describe("loadExploited — degraded sources and response guards", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  const cisaOk = { ok: true, json: async () => CISA_KEV };
  const route = (euvd: unknown) =>
    vi.fn(async (url: string) => (url.includes("euvdservices") ? euvd : cisaOk));

  it("reports source 'euvd' after a successful EUVD load", async () => {
    vi.stubGlobal("fetch", route({ ok: true, headers: jsonHeaders, json: async () => FULL_DUMP }));
    const { loadExploited, getExploitedSource } = await import("../euvd.js");
    await loadExploited();
    expect(getExploitedSource()).toBe("euvd");
    vi.unstubAllGlobals();
  });

  it.each([
    ["403 with empty body (WAF/UA block)", { ok: false, status: 403, json: async () => { throw new SyntaxError("empty"); } }],
    ["HTML error page with status 200", { ok: true, headers: { get: () => "text/html" }, json: async () => { throw new SyntaxError("<html>"); } }],
    ["truncated dump", { ok: true, headers: jsonHeaders, json: async () => KEV_DUMP }],
    ["empty array", { ok: true, headers: jsonHeaders, json: async () => [] }],
    ["429 rate limited", { ok: false, status: 429, json: async () => ({}) }],
  ])("falls back to CISA and reports 'cisa-fallback' on %s", async (_label, euvdResponse) => {
    vi.stubGlobal("fetch", route(euvdResponse));
    const { loadExploited, getExploitedSource } = await import("../euvd.js");
    const result = await loadExploited();
    expect(getExploitedSource()).toBe("cisa-fallback");
    expect(result.get("CVE-2021-22555")?.sources).toEqual(["cisa_kev"]);
    expect(result.has("CVE-2015-7501")).toBe(false); // EU KEV is missing in fallback mode
    vi.unstubAllGlobals();
  });

  it("reports 'none' when EUVD and CISA both fail", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    const { loadExploited, getExploitedSource } = await import("../euvd.js");
    await loadExploited();
    expect(getExploitedSource()).toBe("none");
    vi.unstubAllGlobals();
  });

  it("drops entries with a non-ISO dateAdded to null", async () => {
    const dump = [...FILLER, { cveId: "CVE-2026-1", euvdId: "EUVD-2026-1", dateAdded: "Sep 9, 2026", sources: ["eukev_kev"] }];
    vi.stubGlobal("fetch", route({ ok: true, headers: jsonHeaders, json: async () => dump }));
    const { loadExploited } = await import("../euvd.js");
    expect((await loadExploited()).get("CVE-2026-1")?.dateAdded).toBeNull();
    vi.unstubAllGlobals();
  });
});

describe("loadEuvdMapping — request and CSV quirks", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("sends a User-Agent and tolerates CRLF line endings", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => "euvd_id,cve_id\r\nEUVD-2021-0001,CVE-2021-23337\r\n" });
    vi.stubGlobal("fetch", fetchMock);
    const { loadEuvdMapping } = await import("../euvd.js");
    const map = await loadEuvdMapping();
    expect(fetchMock.mock.calls[0][1]?.headers?.["User-Agent"]).toContain("OtterSight");
    expect(map.get("CVE-2021-23337")).toBe("EUVD-2021-0001");
    vi.unstubAllGlobals();
  });
});

describe("lookupEuvdRecord — unscored records and aliases", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  const record = (over: Record<string, unknown>) => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ id: "EUVD-2026-1", aliases: "GHSA-jfh8-c2jp-5v3q\nCVE-2021-44228\n", ...over }),
  });

  it("reports EPSS as unknown (null) for unscored records, not 0 %", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(record({ baseScore: 0, epss: 0 })));
    const { lookupEuvdRecord } = await import("../euvd.js");
    const r = await lookupEuvdRecord("EUVD-2026-1");
    expect(r?.baseScore).toBeNull();
    expect(r?.epss).toBeNull();
    vi.unstubAllGlobals();
  });

  it("treats EPSS 0 as unknown even on scored records (FIRST never publishes 0)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(record({ baseScore: 5.3, baseScoreVersion: "3.1", epss: 0 })));
    const { lookupEuvdRecord } = await import("../euvd.js");
    expect((await lookupEuvdRecord("EUVD-2026-1"))?.epss).toBeNull();
    vi.unstubAllGlobals();
  });

  it("keeps GHSA-first alias order intact", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(record({ baseScore: 10, baseScoreVersion: "3.1", epss: 97.5 })));
    const { lookupEuvdRecord } = await import("../euvd.js");
    const r = await lookupEuvdRecord("EUVD-2026-1");
    expect(r?.aliases).toEqual(["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"]);
    expect(r?.epss).toBe(0.975);
    vi.unstubAllGlobals();
  });

  it.each([
    ["400 text/plain", { ok: false, status: 400, text: async () => "Required request parameter 'id'" }],
    ["404 text/plain", { ok: false, status: 404, text: async () => "Not Found" }],
    ["200 with HTML body", { ok: true, status: 200, text: async () => "<html>502 Bad Gateway</html>" }],
  ])("returns null without throwing on %s", async (_label, res) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(res));
    const { lookupEuvdRecord } = await import("../euvd.js");
    expect(await lookupEuvdRecord("EUVD-2026-1")).toBeNull();
    vi.unstubAllGlobals();
  });
});

describe("loadExploited — CISA cross-check of EUVD KEV entries", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  const dump = [
    ...FILLER,
    // Removed from CISA within an hour on 2026-08-21, still listed by EUVD
    { cveId: "CVE-2026-69836", euvdId: "EUVD-2026-69836", dateAdded: "2026-08-21", sources: ["cisa_kev"] },
    // In both catalogues according to EUVD, but gone from CISA → keep EU KEV only
    { cveId: "CVE-2026-50000", euvdId: "EUVD-2026-50000", dateAdded: "2026-07-01", sources: ["cisa_kev", "eukev_kev"] },
    { cveId: "CVE-2015-7501", euvdId: "EUVD-2022-3799", dateAdded: "2025-07-14", sources: ["eukev_kev"] },
  ];
  const cisa = { vulnerabilities: FILLER.map((f) => ({ cveID: f.cveId })) };
  const route = (cisaResponse: unknown) =>
    vi.fn(async (url: string) =>
      url.includes("euvdservices") ? { ok: true, headers: jsonHeaders, json: async () => dump } : cisaResponse,
    );

  it("drops CISA-only entries that CISA has removed and strips cisa_kev from mixed ones", async () => {
    vi.stubGlobal("fetch", route({ ok: true, json: async () => cisa }));
    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(result.has("CVE-2026-69836")).toBe(false);
    expect(result.get("CVE-2026-50000")?.sources).toEqual(["eukev_kev"]);
    expect(result.get("CVE-2015-7501")?.sources).toEqual(["eukev_kev"]);
    expect(result.get(FILLER[0].cveId)?.sources).toEqual(["cisa_kev"]);
    vi.unstubAllGlobals();
  });

  it("keeps EUVD data unchanged when the CISA catalogue is unavailable", async () => {
    vi.stubGlobal("fetch", route({ ok: false, status: 503 }));
    const { loadExploited, getExploitedSource } = await import("../euvd.js");
    const result = await loadExploited();

    expect(result.get("CVE-2026-69836")?.sources).toEqual(["cisa_kev"]);
    expect(getExploitedSource()).toBe("euvd");
    vi.unstubAllGlobals();
  });
});
