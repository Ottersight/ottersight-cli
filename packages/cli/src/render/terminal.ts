import Table from "cli-table3";
import chalk from "chalk";
import type { EnrichedVuln } from "@ottersight/scanner";

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  negligible: (s) => chalk.gray(s),
  unknown: (s) => chalk.gray(s),
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];

export function renderTerminalTable(vulns: EnrichedVuln[]): string {
  const table = new Table({
    head: ["Package", "Version", "CVE", "Severity", "EUVD", "KEV", "Fix"],
    style: { head: ["white", "bold"] },
  });

  const sorted = [...vulns].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) -
      SEVERITY_ORDER.indexOf(b.severity.toLowerCase())
  );

  for (const v of sorted) {
    const sev = v.severity.toLowerCase();
    const colorFn = SEVERITY_COLOR[sev] ?? ((s: string) => chalk.gray(s));
    table.push([
      v.packageName,
      v.packageVersion,
      v.cveId,
      colorFn(v.severity.toUpperCase()),
      v.euvdId ?? "",
      v.inKev ? "\u26A0" : "",
      v.fixVersion ?? "none",
    ]);
  }

  return table.toString();
}

export function renderSummaryLine(vulns: EnrichedVuln[]): string {
  const total = vulns.length;
  if (total === 0) return "No vulnerabilities found";

  const counts: Record<string, number> = {};
  for (const v of vulns) {
    const sev = v.severity.toLowerCase();
    counts[sev] = (counts[sev] ?? 0) + 1;
  }

  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }

  return `${total} vulnerabilities found (${parts.join(", ")})`;
}
