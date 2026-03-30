import { log } from "./logger.js";

// GitHub mirror — CISA blocks datacenter IPs directly
// Source: https://github.com/cisagov/kev-data (CC0 licensed, synced within minutes of cisa.gov)
const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

let kevSet: Set<string> | null = null;
let kevLoadedAt = 0;

interface KevCatalog {
  vulnerabilities: Array<{ cveID: string }>;
}

export async function loadKev(): Promise<Set<string>> {
  if (kevSet && Date.now() - kevLoadedAt < MAX_AGE_MS) {
    return kevSet;
  }

  try {
    const res = await fetch(KEV_URL, {
      headers: {
        "User-Agent": "OtterSight/1.0 (Security Scanner; +https://ottersight.com)",
        "Accept": "application/json",
      },
    });
    if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
    const data = (await res.json()) as KevCatalog;
    kevSet = new Set(data.vulnerabilities.map((v) => v.cveID));
    kevLoadedAt = Date.now();
    log.info("KEV catalog loaded", { entries: kevSet.size });
    return kevSet;
  } catch (err) {
    log.error("Failed to load KEV catalog", { error: err instanceof Error ? err.message : String(err) });
    return kevSet ?? new Set();
  }
}

export async function isKnownExploited(cveId: string): Promise<boolean> {
  const set = await loadKev();
  return set.has(cveId);
}
