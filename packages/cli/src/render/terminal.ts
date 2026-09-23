import Table from "cli-table3";
import chalk from "chalk";
import { formatExploited, formatEpss, DATA_ATTRIBUTION, type EnrichedVuln } from "@ottersight/scanner";

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  negligible: (s) => chalk.gray(s),
  unknown: (s) => chalk.gray(s),
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];

// Severity first; within a severity, known-exploited findings come first.
export function compareVulns(a: EnrichedVuln, b: EnrichedVuln): number {
  const bySeverity =
    SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) - SEVERITY_ORDER.indexOf(b.severity.toLowerCase());
  if (bySeverity !== 0) return bySeverity;
  return Number(b.exploitedSources.length > 0) - Number(a.exploitedSources.length > 0);
}

export function renderTerminalTable(vulns: EnrichedVuln[]): string {
  const table = new Table({
    head: ["Package", "Version", "EUVD", "Advisory", "Severity", "CVSS", "EPSS", "Exploited", "Fix"],
    style: { head: ["white", "bold"] },
  });

  const sorted = [...vulns].sort(compareVulns);

  for (const v of sorted) {
    const sev = v.severity.toLowerCase();
    const colorFn = SEVERITY_COLOR[sev] ?? ((s: string) => chalk.gray(s));
    table.push([
      v.packageName,
      v.packageVersion,
      v.euvdId ?? "",
      v.cveId,
      colorFn(v.severity.toUpperCase()),
      v.cvss?.toFixed(1) ?? "",
      formatEpss(v.epss),
      v.exploitedSources.length > 0 ? chalk.red.bold(`\u26A0 ${formatExploited(v)}`) : "",
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

  const exploited = vulns.filter((v) => v.exploitedSources.length > 0);
  const euOnly = exploited.filter((v) => !v.exploitedSources.includes("cisa_kev")).length;
  let line = `${total} vulnerabilities found (${parts.join(", ")})`;
  if (exploited.length > 0) {
    line += ` · ${exploited.length} known exploited`;
    if (euOnly > 0) line += ` (${euOnly} only in EU KEV)`;
  }
  return line;
}

export function renderAttribution(): string {
  return DATA_ATTRIBUTION;
}
