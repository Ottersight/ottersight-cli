import path from "node:path";
import { scanLocal, loadKev, loadEuvdMapping } from "@ottersight/scanner";
import { enrichVulnerabilities } from "../enrich.js";
import { renderMcpMarkdown } from "../render/markdown.js";
import type { EnrichedVuln } from "@ottersight/scanner";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];
const CTA = "Full SBOM, component tracking, and scheduled scans -> ottersight.com";

export async function handleScan(input: { path: string }) {
  const resolvedPath = path.resolve(input.path);

  const [scanResult, kevSet, euvdMap] = await Promise.all([
    scanLocal({ path: resolvedPath, timeout: 120_000 }),
    loadKev(),
    loadEuvdMapping(),
  ]);

  const enriched = enrichVulnerabilities(
    scanResult.grype.matches ?? [],
    kevSet,
    euvdMap,
  );

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

  const text = renderMcpMarkdown(displayVulns, counts, truncated);

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      scannedPath: resolvedPath,
      vulnerabilities: sorted,
      truncated,
      summary: counts,
      cta: CTA,
    },
  };
}
