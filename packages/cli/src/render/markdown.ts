import type { EnrichedVuln } from "@ottersight/scanner";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];

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

  // Summary counts
  const counts: Record<string, number> = {};
  for (const v of vulns) {
    const sev = v.severity.toLowerCase();
    counts[sev] = (counts[sev] ?? 0) + 1;
  }
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }
  const summaryText =
    total === 0
      ? "No vulnerabilities found"
      : `${total} vulnerabilities found (${parts.join(", ")})`;

  if (total === 0) {
    return `${badge}\n\n${summaryText}\n`;
  }

  // Sort vulns by severity
  const sorted = [...vulns].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) -
      SEVERITY_ORDER.indexOf(b.severity.toLowerCase())
  );

  // Table rows — no ANSI codes, only plain text + unicode emoji
  const rows = sorted.map((v) => {
    const sev = v.severity.toLowerCase();
    const emoji = SEVERITY_EMOJI[sev] ?? "";
    return `| ${v.packageName} | ${v.packageVersion} | ${v.cveId} | ${emoji} ${v.severity.toUpperCase()} | ${v.euvdId ?? "-"} | ${v.inKev ? "\u26A0\uFE0F" : "-"} | ${v.fixVersion ?? "none"} |`;
  });

  const tableHeader = `| Package | Version | CVE | Severity | EUVD | KEV | Fix |\n| --- | --- | --- | --- | --- | --- | --- |`;

  const detailsBlock = `<details>\n<summary>Full vulnerability report</summary>\n\n${tableHeader}\n${rows.join("\n")}\n\n</details>`;

  return `${badge}\n\n**${summaryText}**\n\n${detailsBlock}\n`;
}
