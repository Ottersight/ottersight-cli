import { describe, it, expect } from "vitest";
import type { EnrichedVuln } from "@ottersight/scanner";
import { renderTerminalTable, renderSummaryLine, renderAttribution } from "../render/terminal.js";
import { renderMarkdown } from "../render/markdown.js";

const testVulns: EnrichedVuln[] = [
  {
    packageName: "lodash",
    packageVersion: "4.17.20",
    cveId: "CVE-2021-23337",
    severity: "critical",
    euvdId: "EUVD-2021-0001",
    inKev: true,
    exploitedSources: ["eukev_kev"],
    exploitedSince: "2025-07-14",
    cvss: 7.2,
    epss: 0.21333,
    fixVersion: "4.17.21",
  },
  {
    packageName: "express",
    packageVersion: "4.17.0",
    cveId: "CVE-2024-1234",
    severity: "high",
    euvdId: null,
    inKev: false,
    exploitedSources: [],
    exploitedSince: null,
    cvss: null,
    epss: null,
    fixVersion: "4.18.0",
  },
  {
    packageName: "qs",
    packageVersion: "6.5.2",
    cveId: "CVE-2022-5678",
    severity: "medium",
    euvdId: null,
    inKev: false,
    exploitedSources: [],
    exploitedSince: null,
    cvss: null,
    epss: null,
    fixVersion: null,
  },
  {
    packageName: "debug",
    packageVersion: "3.1.0",
    cveId: "CVE-2023-9999",
    severity: "low",
    euvdId: null,
    inKev: false,
    exploitedSources: [],
    exploitedSince: null,
    cvss: null,
    epss: null,
    fixVersion: "3.2.0",
  },
];

describe("renderTerminalTable", () => {
  it("sorts vulns CRITICAL to LOW", () => {
    const output = renderTerminalTable(testVulns);
    const criticalIdx = output.indexOf("CRITICAL");
    const lowIdx = output.indexOf("LOW");
    expect(criticalIdx).toBeGreaterThanOrEqual(0);
    expect(lowIdx).toBeGreaterThanOrEqual(0);
    expect(criticalIdx).toBeLessThan(lowIdx);
  });

  it("shows the exploited flag with its source (EU KEV)", () => {
    const output = renderTerminalTable(testVulns);
    // lodash is in EU KEV — should show ⚠ (U+26A0) and the source label
    expect(output).toContain("\u26A0");
    expect(output).toContain("EU KEV");
  });

  it("puts the EUVD column before the advisory column and shows CVSS/EPSS", () => {
    const output = renderTerminalTable(testVulns);
    const header = output.split("\n")[1];
    expect(header.indexOf("EUVD")).toBeLessThan(header.indexOf("Advisory"));
    expect(output).toContain("7.2");
    expect(output).toContain("21.3%");
  });
});

describe("renderSummaryLine", () => {
  it("produces correct count format with multiple severities", () => {
    const result = renderSummaryLine(testVulns);
    expect(result).toBe(
      "4 vulnerabilities found (1 critical, 1 high, 1 medium, 1 low) · 1 known exploited (1 only in EU KEV)"
    );
  });

  it("omits the exploited suffix when nothing is known exploited", () => {
    const result = renderSummaryLine(testVulns.slice(1));
    expect(result).toBe("3 vulnerabilities found (1 high, 1 medium, 1 low)");
  });

  it("attribution acknowledges ENISA EUVD as source", () => {
    expect(renderAttribution()).toContain("ENISA EU Vulnerability Database (EUVD), source acknowledged");
  });

  it('returns "No vulnerabilities found" for empty array', () => {
    const result = renderSummaryLine([]);
    expect(result).toBe("No vulnerabilities found");
  });
});

describe("renderMarkdown", () => {
  it("outputs valid Markdown with no ANSI codes", () => {
    const output = renderMarkdown(testVulns);
    // Must not contain ANSI escape sequences
    expect(output).not.toMatch(/\x1b\[/);
  });

  it("includes shields.io badge URL", () => {
    const output = renderMarkdown(testVulns);
    expect(output).toContain("shields.io/badge");
  });

  it("includes collapsible details block", () => {
    const output = renderMarkdown(testVulns);
    expect(output).toContain("<details>");
    expect(output).toContain("</details>");
  });

  it("shows EUVD-first columns, EU KEV and the ENISA attribution", () => {
    const output = renderMarkdown(testVulns);
    expect(output).toContain("| Package | Version | EUVD | Advisory | Severity | CVSS | EPSS | Exploited | Fix |");
    expect(output).toContain("EU KEV");
    expect(output).toContain("source acknowledged");
  });

  it("includes summary line with vulnerability count", () => {
    const output = renderMarkdown(testVulns);
    expect(output).toContain("4 vulnerabilities found");
  });
});
