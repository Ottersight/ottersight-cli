import { describe, it, expect } from "vitest";
import type { EnrichedVuln } from "@ottersight/scanner";
import { renderSarif } from "../render/sarif.js";

const vulns: EnrichedVuln[] = [
  {
    packageName: "lodash",
    packageVersion: "4.17.20",
    cveId: "CVE-2021-23337",
    severity: "critical",
    euvdId: "EUVD-2021-0001",
    inKev: true,
    fixVersion: "4.17.21",
    locations: ["package-lock.json", "apps/web/package-lock.json"],
  },
  {
    packageName: "lodash",
    packageVersion: "4.0.0",
    cveId: "CVE-2021-23337",
    severity: "critical",
    euvdId: null,
    inKev: false,
    fixVersion: "4.17.21",
    locations: ["legacy/package-lock.json"],
  },
  {
    packageName: "qs",
    packageVersion: "6.5.2",
    cveId: "GHSA-hrpp-h998-j3pp",
    severity: "medium",
    euvdId: null,
    inKev: false,
    fixVersion: null,
  },
];

describe("renderSarif", () => {
  const log = JSON.parse(renderSarif(vulns, "1.2.3"));
  const run = log.runs[0];

  it("produces a SARIF 2.1.0 envelope", () => {
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-2.1.0");
    expect(run.tool.driver.name).toBe("OtterSight");
    expect(run.tool.driver.version).toBe("1.2.3");
  });

  it("emits one rule per vulnerability ID", () => {
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual([
      "CVE-2021-23337",
      "GHSA-hrpp-h998-j3pp",
    ]);
  });

  it("maps severity to level and GitHub security-severity", () => {
    const [cve, ghsa] = run.tool.driver.rules;
    expect(cve.defaultConfiguration.level).toBe("error");
    expect(cve.properties["security-severity"]).toBe("9.5");
    expect(ghsa.defaultConfiguration.level).toBe("warning");
    expect(ghsa.properties["security-severity"]).toBe("5.5");
  });

  it("links help to NVD for CVEs and GitHub advisories for GHSA", () => {
    const [cve, ghsa] = run.tool.driver.rules;
    expect(cve.helpUri).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
    expect(ghsa.helpUri).toBe("https://github.com/advisories/GHSA-hrpp-h998-j3pp");
  });

  it("tags KEV-listed vulnerabilities", () => {
    expect(run.tool.driver.rules[0].properties.tags).toContain("kev");
    expect(run.tool.driver.rules[1].properties.tags).not.toContain("kev");
  });

  it("emits one result per vuln with all locations", () => {
    expect(run.results).toHaveLength(3);
    const uris = run.results[0].locations.map(
      (l: { physicalLocation: { artifactLocation: { uri: string } } }) => l.physicalLocation.artifactLocation.uri,
    );
    expect(uris).toEqual(["package-lock.json", "apps/web/package-lock.json"]);
  });

  it("includes KEV, EUVD and fix info in the message", () => {
    const text = run.results[0].message.text;
    expect(text).toContain("lodash@4.17.20");
    expect(text).toContain("CISA KEV");
    expect(text).toContain("EUVD-2021-0001");
    expect(text).toContain("Fixed in 4.17.21");
    expect(run.results[2].message.text).toContain("No fix available");
  });

  it("uses stable, distinct fingerprints per package version", () => {
    const fps = run.results.map((r: { partialFingerprints: Record<string, string> }) => r.partialFingerprints["ottersight/v1"]);
    expect(new Set(fps).size).toBe(3);
  });

  it("renders an empty but valid log for zero vulns", () => {
    const empty = JSON.parse(renderSarif([], "1.2.3"));
    expect(empty.runs[0].results).toEqual([]);
    expect(empty.runs[0].tool.driver.rules).toEqual([]);
  });
});
