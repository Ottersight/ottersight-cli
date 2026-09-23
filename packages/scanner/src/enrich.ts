import type { GrypeMatch, EnrichedVuln } from "./types.js";
import type { ExploitedInfo } from "./euvd.js";

/** Attribution for every output that shows enriched findings. ENISA requires the source to be acknowledged. */
export const DATA_ATTRIBUTION =
  "Vulnerability data: ENISA EU Vulnerability Database (EUVD), source acknowledged · Anchore Grype DB · CISA KEV · FIRST EPSS";

// Grype uses GHSA IDs as the primary vulnerability ID for many advisories.
// The real CVE ID (needed for EUVD and KEV lookups) lives in relatedVulnerabilities.
export function resolveCveId(m: GrypeMatch): string {
  if (m.vulnerability.id.startsWith("CVE-")) return m.vulnerability.id;
  const related = m.relatedVulnerabilities ?? [];
  return related.find((r) => r.id.startsWith("CVE-"))?.id ?? m.vulnerability.id;
}

type CvssEntry = { metrics?: { baseScore?: number }; version?: string };

// Prefer the newest CVSS version; the advisory's own scores win over the related CVE record.
function pickCvss(m: GrypeMatch): number | null {
  const best = (entries: CvssEntry[] | undefined): number | null => {
    const scored = (entries ?? []).filter((c) => typeof c.metrics?.baseScore === "number");
    if (scored.length === 0) return null;
    scored.sort((a, b) => parseFloat(b.version ?? "0") - parseFloat(a.version ?? "0"));
    return scored[0].metrics!.baseScore!;
  };
  const own = best(m.vulnerability.cvss);
  if (own !== null) return own;
  for (const r of m.relatedVulnerabilities ?? []) {
    const score = best(r.cvss);
    if (score !== null) return score;
  }
  return null;
}

function pickEpss(m: GrypeMatch): number | null {
  const scores = (m.vulnerability.epss ?? [])
    .map((e) => e.epss)
    .filter((e): e is number => typeof e === "number");
  return scores.length > 0 ? Math.max(...scores) : null;
}

export function enrichVulnerabilities(
  matches: GrypeMatch[],
  exploited: Map<string, ExploitedInfo>,
  euvdMap: Map<string, string>,
): EnrichedVuln[] {
  // Dedup: same package + version + vuln ID can appear multiple times when
  // Grype scans several manifest/lockfile occurrences of the same package.
  // Locations of the duplicates are merged into the first occurrence.
  const seen = new Map<string, EnrichedVuln>();
  const vulns: EnrichedVuln[] = [];

  for (const m of matches) {
    const key = `${m.artifact.name}@${m.artifact.version}:${m.vulnerability.id}`;
    const paths = (m.artifact.locations ?? []).map((l) => l.path.replace(/^\/+/, ""));
    const existing = seen.get(key);
    if (existing) {
      for (const p of paths) {
        if (!existing.locations!.includes(p)) existing.locations!.push(p);
      }
      continue;
    }

    const cveId = resolveCveId(m);
    const kev = exploited.get(cveId);
    const vuln: EnrichedVuln = {
      packageName: m.artifact.name,
      packageVersion: m.artifact.version,
      cveId: m.vulnerability.id,
      severity: m.vulnerability.severity.toLowerCase(),
      euvdId: euvdMap.get(cveId) ?? kev?.euvdId ?? null,
      inKev: kev !== undefined,
      exploitedSources: kev ? [...kev.sources] : [],
      exploitedSince: kev?.dateAdded ?? null,
      cvss: pickCvss(m),
      epss: pickEpss(m),
      fixVersion: m.vulnerability.fix?.versions?.[0] ?? null,
      locations: [...new Set(paths)],
    };
    seen.set(key, vuln);
    vulns.push(vuln);
  }

  return vulns;
}

/** Short label for the exploited column: "EU KEV", "CISA KEV", "EU + CISA KEV" or "". EU first. */
export function formatExploited(v: Pick<EnrichedVuln, "exploitedSources">): string {
  const eu = v.exploitedSources.includes("eukev_kev");
  const cisa = v.exploitedSources.includes("cisa_kev");
  if (eu && cisa) return "EU + CISA KEV";
  if (eu) return "EU KEV";
  if (cisa) return "CISA KEV";
  return "";
}

/** EPSS as a percentage string ("70.1%"), or "" when unknown. */
export function formatEpss(epss: number | null): string {
  return epss === null ? "" : `${(epss * 100).toFixed(1)}%`;
}
