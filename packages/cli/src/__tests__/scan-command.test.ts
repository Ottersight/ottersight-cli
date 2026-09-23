import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { tmpdir } from "node:os";
import type { GrypeMatch, ExploitedInfo } from "@ottersight/scanner";

vi.mock("@ottersight/scanner", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@ottersight/scanner")>()),
  scanLocal: vi.fn(),
  loadExploited: vi.fn(),
  loadEuvdMapping: vi.fn(),
  loadCveAliases: vi.fn(),
  getExploitedSource: vi.fn(() => "euvd"),
}));
vi.mock("../check-deps.js", () => ({ checkDependencies: vi.fn() }));

const scanner = await import("@ottersight/scanner");
const { scanCommand } = await import("../commands/scan.js");

function match(id: string, severity: string, name = "pkg"): GrypeMatch {
  return { vulnerability: { id, severity }, artifact: { name, version: "1.0.0" } };
}

const MATCHES = [
  match("CVE-2021-44228", "Critical", "log4j-core"),
  match("CVE-2024-0002", "Medium"),
  match("GHSA-aaaa-bbbb-cccc", "Low"),
];
const KEV = new Map<string, ExploitedInfo>([
  ["CVE-2021-44228", { sources: ["cisa_kev", "eukev_kev"], dateAdded: "2021-12-10", euvdId: null }],
]);

let stdout: string[];
let stderr: string[];

beforeEach(() => {
  vi.clearAllMocks();
  process.exitCode = undefined;
  stdout = [];
  stderr = [];
  vi.spyOn(console, "log").mockImplementation((...a) => { stdout.push(a.join(" ")); });
  vi.spyOn(console, "error").mockImplementation((...a) => { stderr.push(a.join(" ")); });
  vi.spyOn(process, "exit").mockImplementation(((code?: number) => { throw new Error(`process.exit(${code})`); }) as never);
  vi.mocked(scanner.scanLocal).mockResolvedValue({
    commitSha: "abc1234", sbom: {}, grype: { matches: MATCHES },
    meta: { cloneSuccess: true, syftExitCode: 0, grypeExitCode: 0, manifestsFound: [] },
  });
  vi.mocked(scanner.loadExploited).mockResolvedValue(KEV);
  vi.mocked(scanner.loadEuvdMapping).mockResolvedValue(new Map([["CVE-2021-44228", "EUVD-2021-9696"]]));
  vi.mocked(scanner.loadCveAliases).mockResolvedValue(new Map());
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

const run = (opts: Parameters<typeof scanCommand>[1]) => scanCommand(tmpdir(), { quiet: true, ...opts });

describe("scanCommand", () => {
  it("--format json: stdout is one JSON document, status goes to stderr", async () => {
    await run({ format: "json", version: "9.9.9", ignore: ["CVE-2024-0002"] });

    expect(stdout).toHaveLength(1);
    const report = JSON.parse(stdout[0]);
    expect(report.tool).toEqual({ name: "ottersight", version: "9.9.9" });
    expect(report.commitSha).toBe("abc1234");
    expect(report.summary).toEqual({ total: 2, bySeverity: { critical: 1, low: 1 }, knownExploited: 1, ignored: 1 });
    expect(report.vulnerabilities[0]).toMatchObject({
      cveId: "CVE-2021-44228", euvdId: "EUVD-2021-9696", exploitedSources: ["cisa_kev", "eukev_kev"],
    });
    expect(stderr.join("\n")).toMatch(/2 vulnerabilities found/);
    expect(process.exitCode).toBe(0);
  });

  it("finishes via process.exitCode, never process.exit (piped stdout must not be cut off)", async () => {
    await run({ format: "sarif" });
    expect(process.exit).not.toHaveBeenCalled();
    expect(JSON.parse(stdout[0]).runs[0].results).toHaveLength(3);
  });

  it.each([
    ["critical", 1],
    ["high", 1],
    ["medium", 1],
    ["kev", 1],
  ] as const)("--fail-on %s fails when a finding qualifies", async (level, code) => {
    await run({ failOn: level });
    expect(process.exitCode).toBe(code);
    expect(stdout.join("\n")).toMatch(/Failing: \d+ finding\(s\)/);
  });

  it("--fail-on passes when nothing qualifies (ignored findings don't count)", async () => {
    vi.mocked(scanner.loadExploited).mockResolvedValue(new Map());
    await run({ failOn: "kev" });
    expect(process.exitCode).toBe(0);

    await run({ failOn: "critical", ignore: ["CVE-2021-44228"] });
    expect(process.exitCode).toBe(0);
    expect(stdout.join("\n")).not.toMatch(/Failing/);
  });

  it("asks OSV by default; not with --no-osv", async () => {
    await run({});
    expect(scanner.loadCveAliases).toHaveBeenCalledTimes(1);
    await run({ osv: false });
    expect(scanner.loadCveAliases).toHaveBeenCalledTimes(1);
  });

  it("--eu-sources: EU-only KEV, no OSV, tool env, notice without mirror", async () => {
    await run({ euSources: true });
    expect(scanner.loadExploited).toHaveBeenCalledWith({ euOnly: true });
    expect(scanner.loadCveAliases).not.toHaveBeenCalled();
    expect(vi.mocked(scanner.scanLocal).mock.calls[0][0]).toMatchObject({ euSources: true, grypeDbUrl: undefined });
    expect(stdout.join("\n")).toMatch(/grype\.anchore\.io/);

    stdout = [];
    await run({ euSources: true, grypeDbUrl: "https://mirror.example.eu/databases" });
    expect(vi.mocked(scanner.scanLocal).mock.calls[1][0]).toMatchObject({ grypeDbUrl: "https://mirror.example.eu/databases" });
    expect(stdout.join("\n")).not.toMatch(/grype\.anchore\.io/);
  });

  it("exits 1 when the scan itself fails", async () => {
    vi.mocked(scanner.scanLocal).mockRejectedValue(new Error("Grype scan failed: boom"));
    await expect(run({})).rejects.toThrow("process.exit(1)");
    expect(stderr.join("\n")).toMatch(/boom/);
  });
});

describe("failingFindings", async () => {
  const { failingFindings } = await import("../fail-on.js");
  const v = (severity: string, kev = false) => ({ severity, exploitedSources: kev ? ["cisa_kev" as const] : [] });

  it("threshold includes higher severities; unknown/negligible never fail", () => {
    const vulns = [v("critical"), v("high"), v("medium"), v("low"), v("negligible"), v("unknown")] as never[];
    expect(failingFindings(vulns, "critical")).toHaveLength(1);
    expect(failingFindings(vulns, "high")).toHaveLength(2);
    expect(failingFindings(vulns, "low")).toHaveLength(4);
  });

  it("kev ignores severity", () => {
    expect(failingFindings([v("low", true), v("critical")] as never[], "kev")).toHaveLength(1);
  });
});
