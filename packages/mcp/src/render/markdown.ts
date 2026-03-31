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

const CTA = "Full SBOM, component tracking, and scheduled scans -> ottersight.com";

export function renderMcpMarkdown(
  vulns: EnrichedVuln[],
  counts: Record<string, number>,
  truncated: boolean,
): string {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  if (vulns.length === 0 && total === 0) {
    return `No vulnerabilities found.\n\n${CTA}\n`;
  }

  // Summary line
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }
  const summaryText =
    total === 0
      ? "No vulnerabilities found"
      : `${total} vulnerabilities found (${parts.join(", ")})`;

  // Sort vulns by severity
  const sorted = [...vulns].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) -
      SEVERITY_ORDER.indexOf(b.severity.toLowerCase())
  );

  // Table rows
  const rows = sorted.map((v) => {
    const sev = v.severity.toLowerCase();
    const emoji = SEVERITY_EMOJI[sev] ?? "";
    return `| ${v.packageName} | ${v.packageVersion} | ${v.cveId} | ${emoji} ${v.severity.toUpperCase()} | ${v.euvdId ?? "-"} | ${v.inKev ? "\u26A0\uFE0F KEV" : "-"} | ${v.fixVersion ?? "none"} |`;
  });

  const tableHeader = `| Package | Version | CVE | Severity | EUVD | KEV | Fix |\n| --- | --- | --- | --- | --- | --- | --- |`;

  let output = `**${summaryText}**\n\n${tableHeader}\n${rows.join("\n")}\n`;

  // Truncation notice (D-06)
  if (truncated) {
    const mediumCount = counts["medium"] ?? 0;
    const lowCount = counts["low"] ?? 0;
    const negligibleCount = counts["negligible"] ?? 0;
    const omitted = mediumCount + lowCount + negligibleCount;
    output += `\nShowing CRITICAL + HIGH only. ${omitted} medium/low omitted. Full details in structured output.\n`;
  }

  // Suggested fixes (D-03)
  const fixable = sorted.filter((v) => v.fixVersion != null);
  if (fixable.length > 0) {
    output += `\n**Suggested fixes:**\n`;
    for (const v of fixable) {
      output += `- ${v.cveId} in ${v.packageName}@${v.packageVersion} -- update to ${v.fixVersion}\n`;
    }
  }

  // CTA (D-09)
  output += `\n${CTA}\n`;

  return output;
}
