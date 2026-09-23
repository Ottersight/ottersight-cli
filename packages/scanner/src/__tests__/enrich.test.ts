import { describe, it, expect } from "vitest";
import type { GrypeMatch } from "../types.js";
import type { ExploitedInfo } from "../euvd.js";
import { enrichVulnerabilities, formatExploited, formatEpss } from "../enrich.js";

const noKev = () => new Map<string, ExploitedInfo>();

function makeMatch(overrides: {
  name: string;
  version: string;
  id: string;
  severity?: string;
  fix?: string;
  related?: Array<{ id: string; severity: string }>;
  locations?: string[];
}): GrypeMatch {
  return {
    vulnerability: {
      id: overrides.id,
      severity: overrides.severity ?? "medium",
      fix: overrides.fix ? { versions: [overrides.fix], state: "fixed" } : undefined,
    },
    artifact: {
      name: overrides.name,
      version: overrides.version,
      locations: overrides.locations?.map((path) => ({ path })),
    },
    relatedVulnerabilities: overrides.related,
  };
}

describe("enrichVulnerabilities", () => {
  describe("deduplication", () => {
    it("removes duplicate (package, version, vuln-id) entries", () => {
      // Simulates step-security/harden-runner appearing in 3 workflow files
      const matches: GrypeMatch[] = [
        makeMatch({ name: "actions/setup-node", version: "v3", id: "GHSA-abcd-1234-efgh" }),
        makeMatch({ name: "actions/setup-node", version: "v3", id: "GHSA-abcd-1234-efgh" }),
        makeMatch({ name: "actions/setup-node", version: "v3", id: "GHSA-abcd-1234-efgh" }),
      ];
      const result = enrichVulnerabilities(matches, noKev(), new Map());
      expect(result).toHaveLength(1);
    });

    it("keeps distinct (package, version, vuln-id) combinations", () => {
      const matches: GrypeMatch[] = [
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337" }),
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2020-8203" }), // different vuln
        makeMatch({ name: "lodash", version: "4.0.0", id: "CVE-2021-23337" }), // different version
      ];
      const result = enrichVulnerabilities(matches, noKev(), new Map());
      expect(result).toHaveLength(3);
    });

    it("preserves first occurrence when deduping", () => {
      const matches: GrypeMatch[] = [
        makeMatch({ name: "express", version: "4.0.0", id: "CVE-2024-1111", fix: "4.1.0" }),
        makeMatch({ name: "express", version: "4.0.0", id: "CVE-2024-1111", fix: "4.2.0" }),
      ];
      const result = enrichVulnerabilities(matches, noKev(), new Map());
      expect(result[0].fixVersion).toBe("4.1.0");
    });
  });

  describe("locations", () => {
    it("strips leading slashes from Grype paths", () => {
      const result = enrichVulnerabilities(
        [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", locations: ["/package-lock.json"] })],
        noKev(),
        new Map(),
      );
      expect(result[0].locations).toEqual(["package-lock.json"]);
    });

    it("merges locations of deduplicated matches", () => {
      const matches: GrypeMatch[] = [
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", locations: ["/package-lock.json"] }),
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", locations: ["/apps/web/package-lock.json"] }),
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337", locations: ["/package-lock.json"] }),
      ];
      const result = enrichVulnerabilities(matches, noKev(), new Map());
      expect(result[0].locations).toEqual(["package-lock.json", "apps/web/package-lock.json"]);
    });

    it("defaults to an empty list when Grype has no locations", () => {
      const result = enrichVulnerabilities(
        [makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337" })],
        noKev(),
        new Map(),
      );
      expect(result[0].locations).toEqual([]);
    });
  });

  describe("EUVD lookup via relatedVulnerabilities", () => {
    it("looks up EUVD using CVE from relatedVulnerabilities when primary ID is GHSA", () => {
      const euvdMap = new Map([["CVE-2023-4567", "EUVD-2023-4567"]]);
      const match = makeMatch({
        name: "lodash",
        version: "4.17.20",
        id: "GHSA-xxxx-yyyy-zzzz",
        related: [{ id: "CVE-2023-4567", severity: "high" }],
      });
      const result = enrichVulnerabilities([match], noKev(), euvdMap);
      expect(result[0].euvdId).toBe("EUVD-2023-4567");
    });

    it("looks up EUVD directly when primary ID is a CVE", () => {
      const euvdMap = new Map([["CVE-2021-23337", "EUVD-2021-23337"]]);
      const match = makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337" });
      const result = enrichVulnerabilities([match], noKev(), euvdMap);
      expect(result[0].euvdId).toBe("EUVD-2021-23337");
    });

    it("returns null euvdId when no CVE ID is found in related", () => {
      const match = makeMatch({
        name: "pkg",
        version: "1.0.0",
        id: "GHSA-xxxx-yyyy-zzzz",
        related: [{ id: "GHSA-other-id", severity: "medium" }],
      });
      const result = enrichVulnerabilities([match], noKev(), new Map());
      expect(result[0].euvdId).toBeNull();
    });
  });

  describe("KEV lookup via relatedVulnerabilities", () => {
    it("marks inKev true when CVE from relatedVulnerabilities is in KEV set", () => {
      const kevSet = new Map<string, ExploitedInfo>([
        ["CVE-2023-9999", { sources: ["cisa_kev"], dateAdded: "2023-05-01", euvdId: null }],
      ]);
      const match = makeMatch({
        name: "openssl",
        version: "1.0.0",
        id: "GHSA-kev-example",
        related: [{ id: "CVE-2023-9999", severity: "critical" }],
      });
      const result = enrichVulnerabilities([match], kevSet, new Map());
      expect(result[0].inKev).toBe(true);
    });

    it("marks inKev false when CVE is not in KEV set", () => {
      const kevSet = new Map<string, ExploitedInfo>([
        ["CVE-9999-0000", { sources: ["cisa_kev"], dateAdded: null, euvdId: null }],
      ]);
      const match = makeMatch({ name: "pkg", version: "1.0.0", id: "CVE-2023-1234" });
      const result = enrichVulnerabilities([match], kevSet, new Map());
      expect(result[0].inKev).toBe(false);
    });
  });

  describe("cveId field in output", () => {
    it("preserves original Grype ID (GHSA) in cveId field for display", () => {
      const match = makeMatch({
        name: "pkg",
        version: "1.0.0",
        id: "GHSA-xxxx-yyyy-zzzz",
        related: [{ id: "CVE-2023-4567", severity: "high" }],
      });
      const result = enrichVulnerabilities([match], noKev(), new Map());
      // Display shows the Grype advisory ID, not the resolved CVE
      expect(result[0].cveId).toBe("GHSA-xxxx-yyyy-zzzz");
    });
  });

  describe("EU KEV / exploited sources", () => {
    // CVE-2015-7501 (Apache Commons Collections) is in ENISA's EU KEV but not in CISA KEV
    const exploited = new Map<string, ExploitedInfo>([
      ["CVE-2015-7501", { sources: ["eukev_kev"], dateAdded: "2025-07-14", euvdId: "EUVD-2022-3799" }],
      ["CVE-2021-44228", { sources: ["cisa_kev", "eukev_kev"], dateAdded: "2021-12-10", euvdId: "EUVD-2021-29270" }],
    ]);

    it("flags an EU-KEV-only CVE resolved via relatedVulnerabilities", () => {
      const match = makeMatch({
        name: "commons-collections",
        version: "3.2.1",
        id: "GHSA-fjq5-5j5f-mvxh",
        related: [{ id: "CVE-2015-7501", severity: "critical" }],
      });
      const [v] = enrichVulnerabilities([match], exploited, new Map());
      expect(v.exploitedSources).toEqual(["eukev_kev"]);
      expect(v.exploitedSince).toBe("2025-07-14");
      expect(v.inKev).toBe(true);
      expect(formatExploited(v)).toBe("EU KEV");
    });

    it("falls back to the EUVD ID from the KEV dump when the mapping has none", () => {
      const match = makeMatch({ name: "commons-collections", version: "3.2.1", id: "CVE-2015-7501" });
      const [v] = enrichVulnerabilities([match], exploited, new Map());
      expect(v.euvdId).toBe("EUVD-2022-3799");
    });

    it("prefers the EUVD mapping over the KEV dump EUVD ID", () => {
      const match = makeMatch({ name: "commons-collections", version: "3.2.1", id: "CVE-2015-7501" });
      const [v] = enrichVulnerabilities([match], exploited, new Map([["CVE-2015-7501", "EUVD-FROM-MAPPING"]]));
      expect(v.euvdId).toBe("EUVD-FROM-MAPPING");
    });

    it("labels entries in both catalogues EU first", () => {
      const match = makeMatch({ name: "log4j-core", version: "2.14.1", id: "CVE-2021-44228" });
      const [v] = enrichVulnerabilities([match], exploited, new Map());
      expect(formatExploited(v)).toBe("EU + CISA KEV");
    });

    it("returns empty sources and null date when not exploited", () => {
      const match = makeMatch({ name: "pkg", version: "1.0.0", id: "CVE-2023-1234" });
      const [v] = enrichVulnerabilities([match], exploited, new Map());
      expect(v.exploitedSources).toEqual([]);
      expect(v.exploitedSince).toBeNull();
      expect(formatExploited(v)).toBe("");
    });
  });

  describe("CVSS and EPSS from Grype", () => {
    it("takes the newest CVSS version from the advisory and the EPSS score", () => {
      const match: GrypeMatch = {
        ...makeMatch({ name: "lodash", version: "4.17.20", id: "GHSA-xxjr-mmjv-4gpg" }),
      };
      match.vulnerability.cvss = [
        { version: "3.1", metrics: { baseScore: 6.5 } },
        { version: "4.0", metrics: { baseScore: 6.9 } },
      ];
      match.vulnerability.epss = [{ cve: "CVE-2025-13465", epss: 0.01782, percentile: 0.8 }];
      const [v] = enrichVulnerabilities([match], noKev(), new Map());
      expect(v.cvss).toBe(6.9);
      expect(v.epss).toBe(0.01782);
      expect(formatEpss(v.epss)).toBe("1.8%");
    });

    it("falls back to the related CVE record's CVSS when the advisory has none", () => {
      const match = makeMatch({ name: "commons-collections", version: "3.2.1", id: "GHSA-6hgm-866r-3cjv" });
      match.relatedVulnerabilities = [
        { id: "CVE-2015-6420", severity: "high", cvss: [{ version: "2.0", metrics: { baseScore: 7.5 } }, { version: "3.1", metrics: { baseScore: 9.8 } }] },
      ];
      const [v] = enrichVulnerabilities([match], noKev(), new Map());
      expect(v.cvss).toBe(9.8);
    });

    it("returns null CVSS/EPSS when Grype has none", () => {
      const [v] = enrichVulnerabilities([makeMatch({ name: "pkg", version: "1", id: "CVE-2023-1" })], noKev(), new Map());
      expect(v.cvss).toBeNull();
      expect(v.epss).toBeNull();
      expect(formatEpss(v.epss)).toBe("");
    });
  });
});
