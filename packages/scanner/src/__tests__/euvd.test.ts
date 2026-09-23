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

describe("loadExploited", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it("parses the EUVD KEV dump incl. EU-KEV-only entries", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => KEV_DUMP });
    vi.stubGlobal("fetch", fetchMock);

    const { loadExploited } = await import("../euvd.js");
    const result = await loadExploited();

    expect(fetchMock.mock.calls[0][0]).toBe("https://euvdservices.enisa.europa.eu/api/kev/dump");
    expect(result.size).toBe(3);
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
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => KEV_DUMP });
    vi.stubGlobal("fetch", fetchMock);

    const { loadExploited } = await import("../euvd.js");
    await loadExploited();
    await loadExploited();

    expect(fetchMock).toHaveBeenCalledTimes(1);

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
