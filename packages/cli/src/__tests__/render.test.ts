import { describe, it, expect } from "vitest";
import type { EnrichedVuln } from "@ottersight/scanner";
import { renderTerminalTable, renderSummaryLine } from "../render/terminal.js";
import { renderMarkdown } from "../render/markdown.js";

const testVulns: EnrichedVuln[] = [
  {
    packageName: "lodash",
    packageVersion: "4.17.20",
    cveId: "CVE-2021-23337",
    severity: "critical",
    euvdId: "EUVD-2021-0001",
    inKev: true,
    fixVersion: "4.17.21",
  },
  {
    packageName: "express",
    packageVersion: "4.17.0",
    cveId: "CVE-2024-1234",
    severity: "high",
    euvdId: null,
    inKev: false,
    fixVersion: "4.18.0",
  },
  {
    packageName: "qs",
    packageVersion: "6.5.2",
    cveId: "CVE-2022-5678",
    severity: "medium",
    euvdId: null,
    inKev: false,
    fixVersion: null,
  },
  {
    packageName: "debug",
    packageVersion: "3.1.0",
    cveId: "CVE-2023-9999",
    severity: "low",
    euvdId: null,
    inKev: false,
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

  it("shows KEV warning flag", () => {
    const output = renderTerminalTable(testVulns);
    // lodash has inKev: true — should show ⚠ (U+26A0)
    expect(output).toContain("\u26A0");
  });
});

describe("renderSummaryLine", () => {
  it("produces correct count format with multiple severities", () => {
    const result = renderSummaryLine(testVulns);
    expect(result).toBe(
      "4 vulnerabilities found (1 critical, 1 high, 1 medium, 1 low)"
    );
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

  it("includes summary line with vulnerability count", () => {
    const output = renderMarkdown(testVulns);
    expect(output).toContain("4 vulnerabilities found");
  });
});
