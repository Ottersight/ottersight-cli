import { log } from "./logger.js";
import { loadKev } from "./kev.js";

const EUVD_MAPPING_URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping";
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

let euvdMap: Map<string, string> | null = null; // CVE-ID → EUVD-ID
let euvdLoadedAt = 0;

export async function loadEuvdMapping(): Promise<Map<string, string>> {
  if (euvdMap && Date.now() - euvdLoadedAt < MAX_AGE_MS) {
    return euvdMap;
  }

  try {
    const res = await fetch(EUVD_MAPPING_URL, {
      headers: { "User-Agent": USER_AGENT, Accept: "text/csv" },
    });
    if (!res.ok) throw new Error(`EUVD fetch failed: ${res.status}`);
    const csv = await res.text();

    euvdMap = new Map();
    const lines = csv.split("\n");
    // Skip header: "euvd_id,cve_id"
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const comma = line.indexOf(",");
      if (comma === -1) continue;
      const euvdId = line.slice(0, comma);
      const cveId = line.slice(comma + 1);
      if (cveId && euvdId) {
        euvdMap.set(cveId, euvdId);
      }
    }

    euvdLoadedAt = Date.now();
    log.info("EUVD mapping loaded", { entries: euvdMap.size });
    return euvdMap;
  } catch (err) {
    log.error("Failed to load EUVD mapping", { error: err instanceof Error ? err.message : String(err) });
    return euvdMap ?? new Map();
  }
}

export async function lookupEuvd(cveId: string): Promise<string | null> {
  const map = await loadEuvdMapping();
  return map.get(cveId) ?? null;
}

// ── Exploited vulnerabilities (EUVD KEV dump) ──
//
// ENISA's EUVD publishes one daily dump (07:00 UTC) that merges CISA KEV with the
// EU KEV (confirmed exploitation against EU entities, reported by the EU CSIRTs
// Network, ENISA or — since 11 Sep 2026 — CRA reports). It is a superset of CISA KEV.
// The endpoint is live but not in ENISA's API docs; the CISA mirror stays as fallback.

const EUVD_KEV_DUMP_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump";
const USER_AGENT = "OtterSight/1.0 (Security Scanner; +https://ottersight.com)";

export type KevSource = "cisa_kev" | "eukev_kev";

export interface ExploitedInfo {
  sources: KevSource[];
  /** ISO date (YYYY-MM-DD) the entry was first added to a KEV catalogue; null if unknown */
  dateAdded: string | null;
  euvdId: string | null;
}

interface EuvdKevEntry {
  cveId?: string;
  euvdId?: string;
  dateAdded?: string;
  sources?: string[];
}

const MIN_KEV_DUMP_ENTRIES = 1000;

/**
 * Where the last loadExploited() result came from:
 * "euvd" (fresh EUVD dump, EU + CISA KEV), "euvd-stale" (EUVD failed, older EUVD data kept),
 * "cisa-fallback" (EUVD failed, CISA KEV only — no EU KEV), "none" (nothing loaded).
 */
export type ExploitedSource = "euvd" | "euvd-stale" | "cisa-fallback" | "none";

let exploitedMap: Map<string, ExploitedInfo> | null = null; // raw EUVD dump, before the CISA cross-check
let exploitedLoadedAt = 0;
let exploitedSource: ExploitedSource = "none";

/** Source of the most recent loadExploited() result; lets callers tell users when EU KEV is missing. */
export function getExploitedSource(): ExploitedSource {
  return exploitedSource;
}

function isKevSource(s: string): s is KevSource {
  return s === "cisa_kev" || s === "eukev_kev";
}

async function fetchEuvdKevDump(): Promise<Map<string, ExploitedInfo>> {
  const res = await fetch(EUVD_KEV_DUMP_URL, {
    headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`EUVD KEV dump fetch failed: ${res.status}`);
  const contentType = res.headers?.get?.("content-type") ?? "";
  if (contentType && !contentType.includes("json")) {
    throw new Error(`EUVD KEV dump: unexpected content-type ${contentType}`);
  }
  const entries = (await res.json()) as EuvdKevEntry[];
  if (!Array.isArray(entries)) throw new Error("EUVD KEV dump: unexpected response shape");
  // The dump has ~1,700 entries; a much smaller one is truncated or broken.
  if (entries.length < MIN_KEV_DUMP_ENTRIES) {
    throw new Error(`EUVD KEV dump: only ${entries.length} entries`);
  }

  const map = new Map<string, ExploitedInfo>();
  for (const e of entries) {
    if (!e.cveId) continue;
    const sources = (e.sources ?? []).filter(isKevSource);
    if (sources.length === 0) continue;
    map.set(e.cveId, {
      sources,
      dateAdded: /^\d{4}-\d{2}-\d{2}$/.test(e.dateAdded ?? "") ? e.dateAdded! : null,
      euvdId: e.euvdId || null,
    });
  }
  return map;
}

/**
 * EUVD keeps CISA entries that CISA has since removed (e.g. CVE-2026-69836: added and removed by
 * CISA within an hour on 2026-08-21, still in the EUVD dump a month later). Drop "cisa_kev" from
 * entries missing in the current CISA catalogue, and drop entries left without a source.
 * Skipped when the CISA catalogue could not be loaded (empty set), so EUVD data is kept as is.
 * Returns a new map; the cached EUVD map is not modified.
 */
function dropStaleCisaEntries(
  euvd: Map<string, ExploitedInfo>,
  cisa: Set<string>,
): Map<string, ExploitedInfo> {
  if (cisa.size === 0) return euvd;
  const map = new Map(euvd);
  let dropped = 0;
  for (const [cveId, info] of map) {
    if (!info.sources.includes("cisa_kev") || cisa.has(cveId)) continue;
    const sources = info.sources.filter((s) => s !== "cisa_kev");
    if (sources.length === 0) map.delete(cveId);
    else map.set(cveId, { ...info, sources });
    dropped++;
  }
  if (dropped > 0) log.info("Dropped stale CISA KEV entries from EUVD dump", { dropped });
  return map;
}

export interface LoadExploitedOptions {
  /**
   * Use ENISA EUVD only: no request to the CISA catalogue (GitHub, US), so no cross-check of
   * withdrawn CISA entries and no CISA fallback when EUVD is unreachable.
   */
  euOnly?: boolean;
  /** CISA KEV catalog URL, e.g. an OtterSight data mirror (then no request goes to GitHub) */
  kevUrl?: string;
}

/**
 * Known exploited vulnerabilities keyed by CVE ID: EUVD KEV dump (CISA KEV + EU KEV),
 * falling back to the CISA KEV mirror, then to an empty map. Never throws.
 */
export async function loadExploited(opts: LoadExploitedOptions = {}): Promise<Map<string, ExploitedInfo>> {
  const finish = async (euvd: Map<string, ExploitedInfo>) =>
    opts.euOnly ? euvd : dropStaleCisaEntries(euvd, await loadKev(opts.kevUrl));

  if (exploitedMap && Date.now() - exploitedLoadedAt < MAX_AGE_MS) {
    exploitedSource = "euvd";
    return finish(exploitedMap);
  }

  try {
    exploitedMap = await fetchEuvdKevDump();
    exploitedLoadedAt = Date.now();
    exploitedSource = "euvd";
    log.info("EUVD KEV dump loaded", { entries: exploitedMap.size });
    return finish(exploitedMap);
  } catch (err) {
    log.error(opts.euOnly ? "Failed to load EUVD KEV dump" : "Failed to load EUVD KEV dump, falling back to CISA KEV", {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  // A stale EUVD map (from an earlier success) still beats CISA-only data.
  if (exploitedMap) {
    exploitedSource = "euvd-stale";
    log.warn("exploited_source_degraded", { source: exploitedSource });
    return finish(exploitedMap);
  }

  // Fallback: CISA only (not in EU-only mode). Not cached, so the next call retries EUVD.
  const fallback = new Map<string, ExploitedInfo>();
  if (!opts.euOnly) {
    for (const cveId of await loadKev(opts.kevUrl)) {
      fallback.set(cveId, { sources: ["cisa_kev"], dateAdded: null, euvdId: null });
    }
  }
  exploitedSource = fallback.size > 0 ? "cisa-fallback" : "none";
  log.warn("exploited_source_degraded", { source: exploitedSource });
  return fallback;
}

// ── EUVD record helpers ──

/**
 * EUVD dates look like "Sep 9, 2026, 1:00:31 PM" (US locale, no timezone).
 * Returns the ISO date (YYYY-MM-DD), treating the value as UTC, or null.
 */
export function parseEuvdDate(s: string | null | undefined): string | null {
  if (!s) return null;
  const d = new Date(s.replace(/,\s(\d{1,2}:)/, " $1") + " UTC");
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/** EUVD `aliases` / `references` are newline-separated strings with a trailing newline. */
export function splitEuvdList(s: string | null | undefined): string[] {
  return (s ?? "").split("\n").map((x) => x.trim()).filter(Boolean);
}

// ── Single EUVD record ──

const EUVD_RECORD_URL = "https://euvdservices.enisa.europa.eu/api/enisaid";

export interface EuvdRecord {
  id: string;
  description: string | null;
  datePublished: string | null;
  dateUpdated: string | null;
  exploitedSince: string | null;
  /** CVSS base score as assigned by the CNA (not NVD); null when EUVD reports 0.0 */
  baseScore: number | null;
  baseScoreVersion: string | null;
  baseScoreVector: string | null;
  /** FIRST EPSS as a 0–1 probability (EUVD publishes it ×100) */
  epss: number | null;
  aliases: string[];
  references: string[];
  assigner: string | null;
}

interface RawEuvdRecord {
  id?: string;
  description?: string;
  datePublished?: string;
  dateUpdated?: string;
  exploitedSince?: string;
  baseScore?: number;
  baseScoreVersion?: string;
  baseScoreVector?: string;
  epss?: number;
  aliases?: string;
  references?: string;
  assigner?: string;
}

/**
 * Fetch one EUVD record by EUVD ID. Returns null when unknown (EUVD answers 204 with an
 * empty body) or on any network/parse error. Never throws.
 */
export async function lookupEuvdRecord(euvdId: string): Promise<EuvdRecord | null> {
  try {
    const res = await fetch(`${EUVD_RECORD_URL}?id=${encodeURIComponent(euvdId)}`, {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
    });
    if (res.status === 204 || !res.ok) return null;
    const body = await res.text();
    if (!body.trim()) return null;
    const r = JSON.parse(body) as RawEuvdRecord;
    if (!r.id) return null;
    return {
      id: r.id,
      description: r.description?.trim() || null,
      datePublished: parseEuvdDate(r.datePublished),
      dateUpdated: parseEuvdDate(r.dateUpdated),
      exploitedSince: parseEuvdDate(r.exploitedSince),
      baseScore: typeof r.baseScore === "number" && r.baseScore > 0 ? r.baseScore : null,
      baseScoreVersion: r.baseScoreVersion || null,
      baseScoreVector: r.baseScoreVector || null,
      // FIRST never publishes an EPSS below 0.0001, so EUVD's 0 always means "no score yet".
      epss: typeof r.epss === "number" && r.epss > 0 ? Math.round(r.epss * 1000) / 100000 : null,
      aliases: splitEuvdList(r.aliases),
      references: splitEuvdList(r.references),
      assigner: r.assigner?.trim() || null,
    };
  } catch (err) {
    log.error("EUVD record lookup failed", { euvdId, error: err instanceof Error ? err.message : String(err) });
    return null;
  }
}
