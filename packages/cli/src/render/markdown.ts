import { formatExploited, formatEpss, DATA_ATTRIBUTION, type EnrichedVuln } from "@ottersight/scanner";
import { compareVulns, renderSummaryLine } from "./terminal.js";

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "\uD83D\uDD34", // Red circle
  high: "\uD83D\uDFE0", // Orange circle
  medium: "\uD83D\uDFE1", // Yellow circle
  low: "\uD83D\uDFE2", // Green circle
  negligible: "\u26AA", // White circle
  unknown: "\u2753", // Question mark
};

export function renderMarkdown(vulns: EnrichedVuln[]): string {
  const total = vulns.length;
  const hasCriticalOrHigh = vulns.some((v) =>
    ["critical", "high"].includes(v.severity.toLowerCase())
  );

  // Badge
  const badgeLabel = hasCriticalOrHigh ? "VULNERABLE" : total > 0 ? "WARNINGS" : "PASS";
  const badgeColor = hasCriticalOrHigh ? "red" : total > 0 ? "yellow" : "green";
  const badge = `![Security: ${badgeLabel}](https://img.shields.io/badge/Security-${badgeLabel}-${badgeColor})`;

  const summaryText = renderSummaryLine(vulns);

  if (total === 0) {
    return `${badge}\n\n${summaryText}\n`;
  }

  // Sort vulns by severity
  const sorted = [...vulns].sort(compareVulns);

  // Table rows — no ANSI codes, only plain text + unicode emoji
  const rows = sorted.map((v) => {
    const sev = v.severity.toLowerCase();
    const emoji = SEVERITY_EMOJI[sev] ?? "";
    const exploited = v.exploitedSources.length > 0 ? `\u26A0\uFE0F ${formatExploited(v)}` : "-";
    return `| ${v.packageName} | ${v.packageVersion} | ${v.euvdId ?? "-"} | ${v.cveId} | ${emoji} ${v.severity.toUpperCase()} | ${v.cvss?.toFixed(1) ?? "-"} | ${formatEpss(v.epss) || "-"} | ${exploited} | ${v.fixVersion ?? "none"} |`;
  });

  const tableHeader = `| Package | Version | EUVD | Advisory | Severity | CVSS | EPSS | Exploited | Fix |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |`;

  const detailsBlock = `<details>\n<summary>Full vulnerability report</summary>\n\n${tableHeader}\n${rows.join("\n")}\n\n<sub>${DATA_ATTRIBUTION}</sub>\n\n</details>`;

  return `${badge}\n\n**${summaryText}**\n\n${detailsBlock}\n`;
}
