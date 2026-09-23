import type { EnrichedVuln } from "@ottersight/scanner";

/** `--fail-on` levels: a severity threshold, or "kev" for known-exploited findings (EU or CISA KEV). */
export const FAIL_ON_LEVELS = ["critical", "high", "medium", "low", "kev"] as const;
export type FailOnLevel = (typeof FAIL_ON_LEVELS)[number];

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Findings that make the scan fail for the given `--fail-on` level. */
export function failingFindings(vulns: EnrichedVuln[], level: FailOnLevel): EnrichedVuln[] {
  if (level === "kev") return vulns.filter((v) => v.exploitedSources.length > 0);
  const min = RANK[level];
  return vulns.filter((v) => (RANK[v.severity.toLowerCase()] ?? 0) >= min);
}
