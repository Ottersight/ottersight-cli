// ── Registry lookups for latest stable versions ──

import type { ComponentInput } from "./types.js";

const REQUEST_TIMEOUT = 3000;
const CONCURRENCY = 5;
const DELAY_MS = 200;

async function fetchJson(url: string): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": "OtterSight/1.0" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ── npm ──

async function npmLatest(name: string): Promise<string | null> {
  // npm scoped packages: @scope/name → %40scope%2Fname
  const encodedName = name.startsWith("@") ? name.replace("/", "%2F") : name;
  const data = await fetchJson(`https://registry.npmjs.org/${encodedName}/latest`);
  return data?.version ?? null;
}

// ── PyPI ──

async function pipLatest(name: string): Promise<string | null> {
  const data = await fetchJson(`https://pypi.org/pypi/${name}/json`);
  return data?.info?.version ?? null;
}

// ── Cargo (crates.io) ──

async function cargoLatest(name: string): Promise<string | null> {
  const data = await fetchJson(`https://crates.io/api/v1/crates/${name}`);
  // newest_version excludes yanked versions
  return data?.crate?.newest_version ?? null;
}

// ── Go ──

async function goLatest(module: string): Promise<string | null> {
  // Go proxy returns plain text, not JSON
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    const res = await fetch(`https://proxy.golang.org/${module}/@latest`, {
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = await res.json() as { Version?: string };
    return data?.Version ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ── Composer (Packagist) ──

async function composerLatest(name: string): Promise<string | null> {
  const data = await fetchJson(`https://repo.packagist.org/p2/${name}.json`);
  const packages = data?.packages?.[name];
  if (!Array.isArray(packages) || packages.length === 0) return null;
  // First entry is latest stable
  for (const pkg of packages) {
    const v = pkg.version as string;
    if (v && !v.includes("dev") && !v.includes("alpha") && !v.includes("beta") && !v.includes("RC")) {
      return v.startsWith("v") ? v : v;
    }
  }
  return packages[0]?.version ?? null;
}

// ── Dispatcher ──

async function getLatestVersion(name: string, ecosystem: string | null): Promise<string | null> {
  switch (ecosystem) {
    case "npm": return npmLatest(name);
    case "pip": return pipLatest(name);
    case "cargo": return cargoLatest(name);
    case "go": return goLatest(name);
    case "composer": return composerLatest(name);
    default: return null; // Unsupported ecosystem
  }
}

// ── Batch lookup with rate limiting ──

export async function lookupLatestVersions(
  comps: ComponentInput[]
): Promise<Map<string, { latestVersion: string; isOutdated: boolean }>> {
  const results = new Map<string, { latestVersion: string; isOutdated: boolean }>();

  // Deduplicate by name+ecosystem (same package only looked up once)
  const uniquePackages = new Map<string, string[]>(); // "ecosystem:name" → [component IDs]
  for (const comp of comps) {
    if (!comp.ecosystem) continue;
    const key = `${comp.ecosystem}:${comp.name}`;
    const ids = uniquePackages.get(key) ?? [];
    ids.push(comp.id);
    uniquePackages.set(key, ids);
  }

  const entries = [...uniquePackages.entries()];

  // Process in batches of CONCURRENCY
  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const batch = entries.slice(i, i + CONCURRENCY);
    const promises = batch.map(async ([key, compIds]) => {
      const [ecosystem, ...nameParts] = key.split(":");
      const name = nameParts.join(":"); // Handle scoped packages like @scope/name

      const latestVersion = await getLatestVersion(name, ecosystem);
      if (!latestVersion) return;

      for (const compId of compIds) {
        const comp = comps.find((c) => c.id === compId);
        if (!comp) continue;
        results.set(compId, {
          latestVersion,
          isOutdated: comp.version !== latestVersion,
        });
      }
    });

    await Promise.all(promises);

    // Rate limiting delay between batches
    if (i + CONCURRENCY < entries.length) {
      await new Promise((r) => setTimeout(r, DELAY_MS));
    }
  }

  return results;
}
