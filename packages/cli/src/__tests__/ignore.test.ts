import { describe, it, expect } from "vitest";
import type { GrypeMatch } from "@ottersight/scanner";
import { filterIgnored } from "../ignore.js";

function makeMatch(id: string, related: string[] = []): GrypeMatch {
  return {
    vulnerability: { id, severity: "high" },
    artifact: { name: "lodash", version: "4.17.20" },
    relatedVulnerabilities: related.map((r) => ({ id: r, severity: "high" })),
  };
}

describe("filterIgnored", () => {
  const matches = [
    makeMatch("CVE-2021-23337"),
    makeMatch("CVE-2020-8203"),
    makeMatch("GHSA-35jh-r3h4-6jhm", ["CVE-2021-99999"]),
  ];

  it("returns all matches when ignore list is empty", () => {
    expect(filterIgnored(matches, [])).toHaveLength(3);
  });

  it("removes matches by primary ID", () => {
    const result = filterIgnored(matches, ["CVE-2021-23337"]);
    expect(result.map((m) => m.vulnerability.id)).toEqual(["CVE-2020-8203", "GHSA-35jh-r3h4-6jhm"]);
  });

  it("supports multiple IDs", () => {
    expect(filterIgnored(matches, ["CVE-2021-23337", "CVE-2020-8203"])).toHaveLength(1);
  });

  it("matches a CVE against GHSA advisories via relatedVulnerabilities", () => {
    const result = filterIgnored(matches, ["CVE-2021-99999"]);
    expect(result.map((m) => m.vulnerability.id)).not.toContain("GHSA-35jh-r3h4-6jhm");
  });

  it("matches GHSA IDs case-insensitively and trims whitespace", () => {
    expect(filterIgnored(matches, [" ghsa-35jh-r3h4-6jhm "])).toHaveLength(2);
  });

  it("ignores unknown IDs without error", () => {
    expect(filterIgnored(matches, ["CVE-0000-0000"])).toHaveLength(3);
  });
});
