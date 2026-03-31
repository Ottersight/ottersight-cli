import { describe, it, expect, vi, beforeEach } from "vitest";
import type { GrypeMatch } from "@ottersight/scanner";

// Mock @ottersight/scanner module
vi.mock("@ottersight/scanner", () => {
  return {
    scanLocal: vi.fn(),
    loadKev: vi.fn(),
    loadEuvdMapping: vi.fn(),
  };
});

function makeMatch(overrides: {
  name: string;
  version: string;
  id: string;
  severity?: string;
  fix?: string;
}): GrypeMatch {
  return {
    vulnerability: {
      id: overrides.id,
      severity: overrides.severity ?? "medium",
      fix: overrides.fix ? { versions: [overrides.fix], state: "fixed" } : undefined,
    },
    artifact: { name: overrides.name, version: overrides.version },
  };
}

function makeFixtureScanResult(matches: GrypeMatch[]) {
  return {
    commitSha: "abc123",
    sbom: { artifacts: [], source: {}, schema: {} } as unknown,
    grype: { matches },
    meta: { scannedAt: new Date().toISOString(), syftVersion: "1.0.0", grypeVersion: "1.0.0" },
  };
}

describe("handleScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns content array with type 'text'", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high" })];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set(["CVE-2021-23337"]));
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-23337", "EUVD-2021-23337"]]));

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    expect(result.content).toBeDefined();
    expect(Array.isArray(result.content)).toBe(true);
    expect(result.content[0].type).toBe("text");
  });

  it("content text contains CVE ID from scan", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high" })];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set(["CVE-2021-23337"]));
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-23337", "EUVD-2021-23337"]]));

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    expect((result.content[0] as { type: string; text: string }).text).toContain("CVE-2021-23337");
  });

  it("structuredContent has vulnerabilities, truncated, summary, cta fields", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high" })];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set(["CVE-2021-23337"]));
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-23337", "EUVD-2021-23337"]]));

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    expect(result.structuredContent).toBeDefined();
    expect(result.structuredContent).toHaveProperty("vulnerabilities");
    expect(result.structuredContent).toHaveProperty("truncated");
    expect(result.structuredContent).toHaveProperty("summary");
    expect(result.structuredContent).toHaveProperty("cta");
  });

  it("structuredContent does NOT have sbom or components (D-08)", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high" })];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set());
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map());

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    expect(result.structuredContent).not.toHaveProperty("sbom");
    expect(result.structuredContent).not.toHaveProperty("components");
  });

  it("structuredContent.cta equals OtterSight Cloud CTA (D-09)", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high" })];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set());
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map());

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    expect(result.structuredContent.cta).toBe("Full SBOM, component tracking, and scheduled scans -> ottersight.com");
  });

  it("D-06: truncates display to CRITICAL+HIGH when >50 vulns, but structuredContent has all", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    // Create 60 vulns: 5 critical, 5 high, 30 medium, 20 low
    const matches: GrypeMatch[] = [
      ...Array.from({ length: 5 }, (_, i) =>
        makeMatch({ name: `critical-pkg-${i}`, version: "1.0.0", id: `CVE-2021-00${i}00`, severity: "critical" })
      ),
      ...Array.from({ length: 5 }, (_, i) =>
        makeMatch({ name: `high-pkg-${i}`, version: "1.0.0", id: `CVE-2021-01${i}00`, severity: "high" })
      ),
      ...Array.from({ length: 30 }, (_, i) =>
        makeMatch({ name: `medium-pkg-${i}`, version: "1.0.0", id: `CVE-2021-02${i}00`, severity: "medium" })
      ),
      ...Array.from({ length: 20 }, (_, i) =>
        makeMatch({ name: `low-pkg-${i}`, version: "1.0.0", id: `CVE-2021-03${i}00`, severity: "low" })
      ),
    ];

    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set());
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map());

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    // All 60 vulns in structuredContent
    expect(result.structuredContent.vulnerabilities).toHaveLength(60);
    expect(result.structuredContent.truncated).toBe(true);

    // Medium-only package names should NOT appear in text output
    const text = (result.content[0] as { type: string; text: string }).text;
    expect(text).not.toContain("medium-pkg-0");
    expect(text).not.toContain("low-pkg-0");

    // Critical and high names SHOULD appear
    expect(text).toContain("critical-pkg-0");
    expect(text).toContain("high-pkg-0");
  });

  it("D-03: fix suggestions appear in Markdown for vulns with fixVersion", async () => {
    const { scanLocal, loadKev, loadEuvdMapping } = await import("@ottersight/scanner");
    const matches = [
      makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", severity: "high", fix: "4.17.21" }),
    ];
    vi.mocked(scanLocal).mockResolvedValue(makeFixtureScanResult(matches) as ReturnType<typeof scanLocal> extends Promise<infer T> ? T : never);
    vi.mocked(loadKev).mockResolvedValue(new Set());
    vi.mocked(loadEuvdMapping).mockResolvedValue(new Map());

    const { handleScan } = await import("../tools/scan.js");
    const result = await handleScan({ path: "/tmp/test-project" });

    const text = (result.content[0] as { type: string; text: string }).text;
    expect(text).toContain("4.17.21");
    expect(text.toLowerCase()).toContain("fix");
  });
});
