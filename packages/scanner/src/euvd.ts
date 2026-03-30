import { log } from "./logger.js";

const EUVD_MAPPING_URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping";
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

let euvdMap: Map<string, string> | null = null; // CVE-ID → EUVD-ID
let euvdLoadedAt = 0;

export async function loadEuvdMapping(): Promise<Map<string, string>> {
  if (euvdMap && Date.now() - euvdLoadedAt < MAX_AGE_MS) {
    return euvdMap;
  }

  try {
    const res = await fetch(EUVD_MAPPING_URL);
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
