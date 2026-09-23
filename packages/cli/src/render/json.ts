import { DATA_ATTRIBUTION, type EnrichedVuln, type ExploitedSource } from "@ottersight/scanner";

export interface JsonReportMeta {
  version: string;
  scannedPath: string;
  commitSha: string;
  exploitedSource: ExploitedSource;
  euSources: boolean;
  ignored: number;
}

/** Machine-readable report: every enriched field of every finding, plus scan metadata. */
export function renderJson(vulns: EnrichedVuln[], meta: JsonReportMeta): string {
  const bySeverity: Record<string, number> = {};
  for (const v of vulns) {
    const sev = v.severity.toLowerCase();
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
  }
  return JSON.stringify(
    {
      tool: { name: "ottersight", version: meta.version },
      scannedPath: meta.scannedPath,
      commitSha: meta.commitSha || null,
      exploitedSource: meta.exploitedSource,
      euSources: meta.euSources,
      dataAttribution: DATA_ATTRIBUTION,
      summary: {
        total: vulns.length,
        bySeverity,
        knownExploited: vulns.filter((v) => v.exploitedSources.length > 0).length,
        ignored: meta.ignored,
      },
      vulnerabilities: vulns,
    },
    null,
    2,
  );
}
