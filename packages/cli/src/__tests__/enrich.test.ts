import { describe, it, expect } from "vitest";
import type { GrypeMatch } from "@ottersight/scanner";
import { enrichVulnerabilities } from "../enrich.js";

function makeMatch(overrides: {
  name: string;
  version: string;
  id: string;
  severity?: string;
  fix?: string;
  related?: Array<{ id: string; severity: string }>;
}): GrypeMatch {
  return {
    vulnerability: {
      id: overrides.id,
      severity: overrides.severity ?? "medium",
      fix: overrides.fix ? { versions: [overrides.fix], state: "fixed" } : undefined,
    },
    artifact: { name: overrides.name, version: overrides.version },
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
      const result = enrichVulnerabilities(matches, new Set(), new Map());
      expect(result).toHaveLength(1);
    });

    it("keeps distinct (package, version, vuln-id) combinations", () => {
      const matches: GrypeMatch[] = [
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337" }),
        makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2020-8203" }), // different vuln
        makeMatch({ name: "lodash", version: "4.0.0", id: "CVE-2021-23337" }), // different version
      ];
      const result = enrichVulnerabilities(matches, new Set(), new Map());
      expect(result).toHaveLength(3);
    });

    it("preserves first occurrence when deduping", () => {
      const matches: GrypeMatch[] = [
        makeMatch({ name: "express", version: "4.0.0", id: "CVE-2024-1111", fix: "4.1.0" }),
        makeMatch({ name: "express", version: "4.0.0", id: "CVE-2024-1111", fix: "4.2.0" }),
      ];
      const result = enrichVulnerabilities(matches, new Set(), new Map());
      expect(result[0].fixVersion).toBe("4.1.0");
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
      const result = enrichVulnerabilities([match], new Set(), euvdMap);
      expect(result[0].euvdId).toBe("EUVD-2023-4567");
    });

    it("looks up EUVD directly when primary ID is a CVE", () => {
      const euvdMap = new Map([["CVE-2021-23337", "EUVD-2021-23337"]]);
      const match = makeMatch({ name: "lodash", version: "4.17.20", id: "CVE-2021-23337" });
      const result = enrichVulnerabilities([match], new Set(), euvdMap);
      expect(result[0].euvdId).toBe("EUVD-2021-23337");
    });

    it("returns null euvdId when no CVE ID is found in related", () => {
      const match = makeMatch({
        name: "pkg",
        version: "1.0.0",
        id: "GHSA-xxxx-yyyy-zzzz",
        related: [{ id: "GHSA-other-id", severity: "medium" }],
      });
      const result = enrichVulnerabilities([match], new Set(), new Map());
      expect(result[0].euvdId).toBeNull();
    });
  });

  describe("KEV lookup via relatedVulnerabilities", () => {
    it("marks inKev true when CVE from relatedVulnerabilities is in KEV set", () => {
      const kevSet = new Set(["CVE-2023-9999"]);
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
      const kevSet = new Set(["CVE-9999-0000"]);
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
      const result = enrichVulnerabilities([match], new Set(), new Map());
      // Display shows the Grype advisory ID, not the resolved CVE
      expect(result[0].cveId).toBe("GHSA-xxxx-yyyy-zzzz");
    });
  });
});
