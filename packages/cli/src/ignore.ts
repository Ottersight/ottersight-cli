import type { GrypeMatch } from "@ottersight/scanner";

// Drops matches whose vulnerability ID — or any related ID — is in the ignore list.
// Matching on related IDs lets `--ignore CVE-…` suppress advisories Grype reports as GHSA-… (and vice versa).
export function filterIgnored(matches: GrypeMatch[], ignore: string[]): GrypeMatch[] {
  if (ignore.length === 0) return matches;
  const ignored = new Set(ignore.map((id) => id.trim().toUpperCase()));

  return matches.filter((m) => {
    const ids = [m.vulnerability.id, ...(m.relatedVulnerabilities ?? []).map((r) => r.id)];
    return !ids.some((id) => ignored.has(id.toUpperCase()));
  });
}
