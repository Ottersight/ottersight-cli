import path from "node:path";
import {
  scanLocal,
  loadExploited,
  loadEuvdMapping,
  loadCveAliases,
  enrichVulnerabilities,
  getExploitedSource,
  DATA_ATTRIBUTION,
} from "@ottersight/scanner";
import { renderMcpMarkdown } from "../render/markdown.js";
import type { EnrichedVuln } from "@ottersight/scanner";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];
const CTA = "Full SBOM, component tracking, and scheduled scans -> ottersight.com";

export async function handleScan(input: { path: string }) {
  const resolvedPath = path.resolve(input.path);

  const [scanResult, exploited, euvdMap] = await Promise.all([
    scanLocal({ path: resolvedPath, timeout: 120_000 }),
    loadExploited(),
    loadEuvdMapping(),
  ]);

  const matches = scanResult.grype.matches ?? [];
  // OTTERSIGHT_NO_OSV=1 keeps GHSA-only findings off OSV.dev (Google, US)
  const cveAliases = process.env.OTTERSIGHT_NO_OSV === "1" ? undefined : await loadCveAliases(matches);
  const enriched = enrichVulnerabilities(matches, exploited, euvdMap, cveAliases);

  // Sort by severity
  const sorted = [...enriched].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) -
      SEVERITY_ORDER.indexOf(b.severity.toLowerCase())
  );

  // Count by severity
  const counts: Record<string, number> = {};
  for (const v of sorted) {
    const sev = v.severity.toLowerCase();
    counts[sev] = (counts[sev] ?? 0) + 1;
  }

  // D-06: truncate display to CRITICAL + HIGH when >50 vulns
  const truncated = sorted.length > 50;
  const displayVulns: EnrichedVuln[] = truncated
    ? sorted.filter((v) => ["critical", "high"].includes(v.severity.toLowerCase()))
    : sorted;

  const exploitedSource = getExploitedSource();
  const degraded =
    exploitedSource === "euvd"
      ? ""
      : exploitedSource === "none"
        ? "\n> Known-exploited data (EUVD, CISA KEV) could not be loaded; exploitation flags are missing.\n"
        : "\n> ENISA EUVD was unreachable; known-exploited data may be incomplete (EU KEV missing or outdated).\n";
  const text = renderMcpMarkdown(displayVulns, counts, truncated) + degraded;

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      scannedPath: resolvedPath,
      vulnerabilities: sorted,
      truncated,
      summary: counts,
      dataAttribution: DATA_ATTRIBUTION,
      exploitedSource,
      cta: CTA,
    },
  };
}
