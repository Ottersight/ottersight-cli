import { log } from "./logger.js";
import { resolveCveId } from "./enrich.js";
import type { GrypeMatch } from "./types.js";

// OSV.dev (Google, US) computes aliases across GHSA/CVE/etc. Used only to find a CVE for
// findings Grype reports as GHSA without any CVE, so EUVD/KEV enrichment can apply to them.
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
const CONCURRENCY = 8;
const TIMEOUT_MS = 10_000;
const BULK_TIMEOUT_MS = 60_000;
const USER_AGENT = "OtterSight/1.0 (Security Scanner; +https://ottersight.com)";

// Advisory ID → CVE aliases (empty = OSV knows no CVE). Failed lookups are not cached.
const cache = new Map<string, { cves: string[]; at: number }>();

/** IDs of matches that have no CVE after `resolveCveId()` and that OSV can resolve (GHSA). */
export function idsNeedingCve(matches: GrypeMatch[]): string[] {
  const ids = new Set<string>();
  for (const m of matches) {
    const id = resolveCveId(m);
    if (id.startsWith("GHSA-")) ids.add(id);
  }
  return [...ids];
}

async function fetchCveAliases(id: string): Promise<string[] | null> {
  try {
    const res = await fetch(OSV_VULN_URL + encodeURIComponent(id), {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 404) return [];
    if (!res.ok) throw new Error(`OSV fetch failed: ${res.status}`);
    if (!res.headers.get("content-type")?.includes("application/json")) {
      throw new Error(`OSV returned ${res.headers.get("content-type") ?? "no content-type"}`);
    }
    const body = (await res.json()) as { aliases?: unknown };
    const aliases = Array.isArray(body.aliases) ? body.aliases : [];
    return aliases.filter((a): a is string => typeof a === "string" && a.startsWith("CVE-"));
  } catch (err) {
    log.warn("osv_lookup_failed", { id, error: err instanceof Error ? err.message : String(err) });
    return null;
  }
}

// Bulk GHSA → CVE map from a data mirror, keyed by mirror URL. Failed loads are not cached.
const bulkCache = new Map<string, { aliases: Map<string, string[]>; at: number }>();

async function loadBulkAliases(url: string): Promise<Map<string, string[]> | null> {
  const hit = bulkCache.get(url);
  if (hit && Date.now() - hit.at < MAX_AGE_MS) return hit.aliases;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
      signal: AbortSignal.timeout(BULK_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`alias map fetch failed: ${res.status}`);
    const body = (await res.json()) as unknown;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("alias map is not an object");
    const aliases = new Map<string, string[]>();
    for (const [id, cves] of Object.entries(body)) {
      if (Array.isArray(cves)) aliases.set(id, cves.filter((c): c is string => typeof c === "string" && c.startsWith("CVE-")));
    }
    bulkCache.set(url, { aliases, at: Date.now() });
    log.info("OSV alias map loaded", { entries: aliases.size });
    return aliases;
  } catch (err) {
    log.warn("osv_alias_map_failed", { url, error: err instanceof Error ? err.message : String(err) });
    return hit?.aliases ?? null;
  }
}

export interface LoadCveAliasesOptions {
  /**
   * GHSA → CVE map from an OtterSight data mirror. The whole map is downloaded and looked up
   * locally, so no advisory ID leaves the machine (not even to the mirror).
   */
  aliasMapUrl?: string;
}

/**
 * CVE aliases for every GHSA-only finding, keyed by advisory ID: from the mirror's alias map
 * when `aliasMapUrl` is set, otherwise one OSV.dev request per advisory.
 * Never throws: failed lookups are simply missing from the result.
 */
export async function loadCveAliases(matches: GrypeMatch[], opts: LoadCveAliasesOptions = {}): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();
  if (opts.aliasMapUrl) {
    const ids = idsNeedingCve(matches);
    if (ids.length === 0) return result;
    const aliases = await loadBulkAliases(opts.aliasMapUrl);
    if (!aliases) return result;
    // The map covers every GHSA advisory, so an ID missing from it has no CVE.
    for (const id of ids) result.set(id, aliases.get(id) ?? []);
    return result;
  }

  const pending: string[] = [];
  for (const id of idsNeedingCve(matches)) {
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < MAX_AGE_MS) result.set(id, hit.cves);
    else pending.push(id);
  }

  let next = 0;
  const worker = async () => {
    while (next < pending.length) {
      const id = pending[next++];
      const cves = await fetchCveAliases(id);
      if (cves === null) continue;
      cache.set(id, { cves, at: Date.now() });
      result.set(id, cves);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, pending.length) }, worker));

  if (pending.length > 0) {
    const resolved = pending.filter((id) => (result.get(id)?.length ?? 0) > 0).length;
    log.info("OSV aliases loaded", { requested: pending.length, resolved });
  }
  return result;
}
