import type { GrypeMatch, EnrichedVuln } from "@ottersight/scanner";

// Grype uses GHSA IDs as the primary vulnerability ID for many advisories.
// The real CVE ID (needed for EUVD and KEV lookups) lives in relatedVulnerabilities.
function resolveCveId(m: GrypeMatch): string {
  if (m.vulnerability.id.startsWith("CVE-")) return m.vulnerability.id;
  const related = m.relatedVulnerabilities ?? [];
  return related.find((r) => r.id.startsWith("CVE-"))?.id ?? m.vulnerability.id;
}

export function enrichVulnerabilities(
  matches: GrypeMatch[],
  kevSet: Set<string>,
  euvdMap: Map<string, string>,
): EnrichedVuln[] {
  // Dedup: same package + version + vuln ID can appear multiple times when
  // Grype scans several manifest/lockfile occurrences of the same package.
  const seen = new Set<string>();
  const vulns: EnrichedVuln[] = [];

  for (const m of matches) {
    const key = `${m.artifact.name}@${m.artifact.version}:${m.vulnerability.id}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const cveId = resolveCveId(m);
    vulns.push({
      packageName: m.artifact.name,
      packageVersion: m.artifact.version,
      cveId: m.vulnerability.id,
      severity: m.vulnerability.severity.toLowerCase(),
      euvdId: euvdMap.get(cveId) ?? null,
      inKev: kevSet.has(cveId),
      fixVersion: m.vulnerability.fix?.versions?.[0] ?? null,
    });
  }

  return vulns;
}
