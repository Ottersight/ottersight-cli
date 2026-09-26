// OtterSight data mirror: re-serves bulk downloads of US-hosted sources, so a scan never queries
// them directly. Upstream providers only see the mirror's full-dataset sync, never which
// advisories or packages a customer has. Layout served under the mirror base URL:
//   /grype/v6/latest.json (+ archive)            Anchore Grype DB, same layout as grype.anchore.io/databases
//   /osv/ghsa-cve.json                           { "GHSA-…": ["CVE-…"] }, built from OSV bulk dumps
//   /kev/known_exploited_vulnerabilities.json    CISA KEV catalog

import type { LoadExploitedOptions } from "./euvd.js";
import type { LoadCveAliasesOptions } from "./osv.js";

export interface MirrorUrls {
  /** Grype DB listing base URL (Grype appends /v6/latest.json) */
  grypeDb: string;
  /** GHSA → CVE alias map */
  osvAliases: string;
  /** CISA KEV catalog */
  kev: string;
}

export function mirrorUrls(base: string): MirrorUrls {
  const root = base.replace(/\/+$/, "");
  return {
    grypeDb: `${root}/grype`,
    osvAliases: `${root}/osv/ghsa-cve.json`,
    kev: `${root}/kev/known_exploited_vulnerabilities.json`,
  };
}

export interface SourceOptions {
  /** No US endpoints at scan time */
  euSources?: boolean;
  /** OtterSight data mirror base URL */
  mirrorUrl?: string;
  /** false: never resolve GHSA-only findings to CVEs */
  osv?: boolean;
}

export interface SourcePlan {
  /** Options for loadExploited() */
  exploited: LoadExploitedOptions;
  /** Options for loadCveAliases(), or null to skip alias resolution */
  aliases: LoadCveAliasesOptions | null;
}

/**
 * Where enrichment data comes from. A mirror replaces every US endpoint (CISA KEV on GitHub,
 * OSV.dev), so with a mirror `euSources` keeps the CISA cross-check and GHSA → CVE resolution;
 * without one, `euSources` drops both.
 */
export function planSources(opts: SourceOptions): SourcePlan {
  const mirror = opts.mirrorUrl ? mirrorUrls(opts.mirrorUrl) : null;
  const euSources = opts.euSources ?? false;
  return {
    exploited: { euOnly: euSources && !mirror, kevUrl: mirror?.kev },
    aliases:
      opts.osv === false ? null
      : mirror ? { aliasMapUrl: mirror.osvAliases }
      : euSources ? null
      : {},
  };
}
