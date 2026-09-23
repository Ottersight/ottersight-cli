# EUVD-First & Digital Sovereignty - Research

**Researched:** 2026-09-23
**Domain:** ENISA EUVD API, EU KEV, Grype DB distribution/mirroring, Syft/Grype runtime network calls, CRA Art. 14/17 + Annex I Part II, EU CSAF sources, claim wording
**Confidence:** HIGH (EUVD API, Grype config: verified live) / MEDIUM (licences, CRA secondary sources, competitor landscape)
**GSD:** Phase-research format. To use with GSD, copy to `.planning/phases/NN-<slug>/NN-RESEARCH.md` once the phase exists in ROADMAP.md (see `tasks/todo.md` for the phase split).

---

<user_constraints>
## User Constraints

### Locked Decisions
- **D-01** OtterSight is positioned as an **EU-sovereign supply-chain scanner & toolkit**; EUVD / digital sovereignty is the focus (2026-09-23).
- **D-02** EUVD must become a **primary data source**, not just a CVE→EUVD-ID label.
- **D-03** Claims must be verifiable: "scans locally" only for CLI & MCP; dashboard = "cloned & scanned in Germany, checkout discarded"; no certifications we don't have.
- **D-04** Graceful degradation stays: EUVD/KEV/registry lookups never throw; network failure → empty data, scan completes.
- **D-05** Research must use Context7 + web search and be GSD-compatible.

### Claude's Discretion
- Where the shared enrichment lives (today `enrich.ts` is duplicated in CLI and MCP).
- Internal EUVD client design (no third-party client).
- Exact CLI flag names (`--eu-sources`, `--provenance`, …).

### Deferred Ideas (OUT OF SCOPE for the first phase)
- Building our own Grype DB (grype-db + vunnel) or an EUVD vunnel provider.
- CSAF ingestion (BSI lister, NCSC-NL) and CSAF VEX export.
- Automatic submission to the ENISA Single Reporting Platform (it has no API).
- Shadowserver honeypot signal (`honeypotObservations`, undocumented).
</user_constraints>

---

## Summary

EUVD is a **catalogue, not a matcher**: product data are free-text CNA strings (no purl, no ecosystem, no CPE, no structured ranges), so Grype stays the matcher and EUVD becomes the primary **enrichment and exploitation** source. The single highest-value change is replacing the CISA-KEV GitHub mirror with EUVD's undocumented-but-live **`/api/kev/dump`**: one 253 KB JSON, 1,733 entries, a strict superset of CISA KEV (1,721/1,721 covered) plus **EU KEV** entries — confirmed exploitation against EU entities, including npm and Maven packages that OtterSight's `inKev` flag misses today (e.g. `@paperclipai/server` CVE-2026-41679, Apache Commons Collections CVE-2015-7501).

Sovereignty at runtime is achievable but must be worded precisely: the Grype DB (≈160 MB `.tar.zst`, schema v6, built daily) is today served from `grype.anchore.io` via **Cloudflare (US)**, and both Syft and Grype call `toolbox-data.anchore.io` for update checks by default. A static **Hetzner mirror** of `databases/v6/latest.json` + archive, plus four env vars, removes every US endpoint at scan time. The *data* still originates mostly from US upstreams (NVD, GHSA, CISA, FIRST EPSS) — say "served from EU infrastructure", never "EU-sourced".

Regulation supports the direction: CRA Art. 14 reporting applies since **11 Sep 2026** (24h/72h/14d) via ENISA's Single Reporting Platform (live, web-only, no API, optional EUVD-ID field). Per Art. 17(5), CRA-reported vulnerabilities reach EUVD only **after a fix exists and with manufacturer consent** — EU KEV is not a live copy of SRP data. No developer-side SCA tool ships EUVD-first today (Dependency-Track #4863 and Trivy #8958 are open), so the window is months, not years.

**Primary recommendation:** Phase 1 = EUVD-first enrichment in the scanner package (KEV dump from EUVD with CISA fallback, `exploitedSources`/`exploitedSince`, EUVD-ID-first outputs, EPSS/CVSS surfaced, ENISA attribution, shared enrichment moved into `@ottersight/scanner`). Phase 2 = sovereign runtime mode (Hetzner DB mirror + env). Phase 3 = provenance report + CRA-ready CycloneDX output. Fix marketing claims immediately (Phase 0).

---

## Standard Stack

### Core (existing, keep)
| Component | Version (verified) | Role |
|---|---|---|
| Grype | 0.118.0, DB schema v6 (v6.1.9) | Package ↔ vulnerability matching (only matcher) |
| Syft | 1.51.1 | SBOM generation |
| Node `fetch` | built-in | EUVD/KEV HTTP |
| Vitest | repo standard | `vi.stubGlobal('fetch')` + `vi.resetModules()` patterns |

### New data endpoints (EUVD, base `https://euvdservices.enisa.europa.eu/api`)
| Endpoint | Use | Notes |
|---|---|---|
| `GET /kev/dump` | **Primary exploited source** | JSON `[{cveId, euvdId, dateAdded:"YYYY-MM-DD", sources:["cisa_kev"\|"eukev_kev"], vendorProject?, product?, vulnerabilityName?}]`, 1,733 entries, regenerated daily 07:00 UTC. Undocumented. |
| `GET /dump/cve-euvd-mapping` | EUVD IDs (already used) | CSV `euvd_id,cve_id`, 378,053 rows, 11.4 MB |
| `GET /enisaid?id=EUVD-…` | Per-finding detail (optional) | EUVD `baseScore`/vector, `epss` (0–100), references; **204 empty body** if unknown |
| `GET /kevEntries/batch?ids=` | Optional: per-source KEV detail incl. `originSource` (CSIRT / `CRA` / `ENISA`) | Undocumented |

### No New Packages Required
Third-party EUVD clients (`@hrbrmstr/euvd` 0.1.2, go-euvd, euvd-cli, PyPI `euvd`) are hobby-grade and none supports `kev/dump`. Write a ~100-line internal client.

---

## Architecture Patterns

### Recommended Structure
```
packages/scanner/src/
├── euvd.ts            # EUVD client: mapping dump + kev/dump + enisaid (+ parsers)
├── kev.ts             # becomes CISA fallback only (or folded into euvd.ts)
├── enrich.ts          # NEW home of enrichVulnerabilities() (moved from cli + mcp)
├── provenance.ts      # Phase 3: which sources/endpoints/versions were used
└── types.ts           # EnrichedVuln extended
packages/cli/src/enrich.ts  → re-export from scanner (or delete)
packages/mcp/src/enrich.ts  → delete copy, import from scanner
```

### Pattern 1: EUVD KEV dump as primary, CISA mirror as fallback
**What:** `loadExploited()` fetches `/api/kev/dump` (24h module cache, custom User-Agent). On failure → current CISA GitHub mirror → empty. Returns `Map<cveId, {sources, dateAdded, euvdId}>`.
**Why:** one fetch, superset of CISA KEV, adds EU KEV; keeps D-04.

### Pattern 2: Extended `EnrichedVuln`
```ts
export interface EnrichedVuln {
  // existing
  packageName: string; packageVersion: string; cveId: string; severity: string;
  euvdId: string | null; inKev: boolean; fixVersion: string | null; locations?: string[];
  // new
  exploitedSources: Array<"cisa_kev" | "eukev_kev">; // [] = not known exploited
  exploitedSince: string | null;   // ISO date (earliest dateAdded across KEV sources)
  cvss: number | null;             // from Grype match (vulnerability.cvss[].metrics.baseScore)
  epss: number | null;             // 0–1, from Grype match (vulnerability.epss) — EUVD value /100 as fallback
}
```
`inKev` stays for backwards compatibility (= `exploitedSources.length > 0`); mark deprecated.

### Pattern 3: Shared enrichment in the scanner package
Move `enrichVulnerabilities()` + `resolveCveId()` into `@ottersight/scanner`. Removes the CLI/MCP duplication noted in CLAUDE.md. The original reason for copying (avoid circular workspace dep) does not apply: scanner → consumers is one-directional.

### Pattern 4: EUVD-ID-first rendering
Terminal/Markdown/SARIF/MCP show `EUVD-… (CVE-…)` when an EUVD ID exists; badge `EU KEV` distinct from `CISA KEV`. SARIF: add tag `eu-kev`, keep `kev`; `properties.exploitedSources`, `properties.euvdId`. Footer/attribution line: "Vulnerability data: ENISA EUVD (source acknowledged), Anchore Grype DB, CISA KEV, FIRST EPSS."

### Pattern 5 (Phase 2): Sovereign runtime env for execFile
```ts
const sovereignEnv = {
  GRYPE_DB_UPDATE_URL: "https://<de-mirror>/databases",   // Grype appends /v6/latest.json
  GRYPE_CHECK_FOR_APP_UPDATE: "false",
  SYFT_CHECK_FOR_APP_UPDATE: "false",
  GRYPE_EXTERNAL_SOURCES_ENABLE: "false",
  // optional: GRYPE_DB_CA_CERT, GRYPE_DB_REQUIRE_UPDATE_CHECK: "true"
};
execFile("grype", args, { env: { ...process.env, ...sovereignEnv } });
```
Plus: skip US registry lookups (npm/PyPI/crates/Go proxy/Packagist) in sovereign mode or label them.

### Pattern 6 (Phase 3): CycloneDX vulnerability source
CycloneDX 1.6 `vulnerabilities[]` supports `source {name, url}`, `references[{id, source}]` (aliases CVE/GHSA/EUVD), `ratings[]`, `analysis {state, justification, response}` (VEX) — confirmed via Context7 `/cyclonedx/cyclonedx-go`.

### Anti-Patterns to Avoid
- Using EUVD product strings to match packages (free text, e.g. `"4.0.0 <4.18.0"`, garbled IBM ranges).
- Bulk-downloading EUVD via `search` (~3,956 calls for 395k entries).
- Calling `enisaid` per finding without a concurrency limit and cache.
- Treating `exploitedSince` as "first seen in the wild" — it is the earliest KEV `dateAdded`.

---

## Don't Hand-Roll

| Problem | Use instead |
|---|---|
| Package matching / version ranges | Grype (keep) |
| Grype DB distribution | Rehost Anchore's `v6/latest.json` + archive; don't build grype-db (yet) |
| EPSS | Grype match `epss` field (FIRST); EUVD `epss`/100 only as fallback |
| CVSS | Grype match `cvss[]`; EUVD `baseScore` = CNA score, no source metadata |
| Air-gapped DB install | `grype db import <file\|url?checksum=sha256:…>` |

---

## Common Pitfalls

### Pitfall 1: EUVD date format
Dates are `"Sep 9, 2026, 1:00:31 PM"` (US locale, 12h, **no timezone**). `kev/dump.dateAdded` is ISO `YYYY-MM-DD`; the EU KEV GitHub JSON uses `YYYY/MM/DD`. Normalise to ISO date strings.

### Pitfall 2: 204 empty body
`enisaid` returns **204 with empty body** for unknown IDs — naive `res.json()` throws. Check `res.status === 204` first.

### Pitfall 3: aliases/references are strings
Newline-separated with a trailing `\n`, inconsistent order (CVE or GHSA first). `split("\n").filter(Boolean)`.

### Pitfall 4: EPSS scale
EUVD `epss` = FIRST × 100 (0–100). `fromEpss`/`toEpss` filters use the same scale. Divide by 100.

### Pitfall 5: silent caps and ignored params
`search` `size` > 100 silently capped; `exploited=false`, `sort`, `order` ignored; pages past the end return `items: []`.

### Pitfall 6: undocumented endpoints can change
`kev/dump`, `kevEntries`, `honeypotObservations` are undocumented; no API versioning or changelog; the apidoc SPA was down during research. Keep the CISA fallback and contract tests with fixtures.

### Pitfall 7: Grype DB age validation
Scan **fails** if the DB is older than 120h (`db.max-allowed-built-age`). A stalled mirror breaks all users within 5 days → monitor the sync; in sovereign mode consider `GRYPE_DB_REQUIRE_UPDATE_CHECK=true` so staleness fails loudly.

### Pitfall 8: DB schema drift
Grype reads only its major schema (v6). Dockerfile uses `:latest` images → pin Grype/Syft versions and mirror every `vN/` in use. Don't rename archives (timestamp parsed from filename; `path` resolved relative to `latest.json`).

### Pitfall 9: DB integrity is sha256 only
No signature; checksum comes from the same `latest.json`. Mirror only after comparing against Anchore's listing; optionally sign our listing (cosign/minisign).

### Pitfall 10: hidden US endpoints
Syft + Grype `check-for-app-update: true` by default (`toolbox-data.anchore.io`, Cloudflare). OtterSight itself calls the KEV GitHub mirror and npm/PyPI/crates/Go/Packagist registries.

### Pitfall 11: Docker image
Distroless runtime ships no DB → every `docker run` downloads ~160 MB and unpacks ~2.2 GB into `/home/nonroot`. Options: bake the DB in, or mount `GRYPE_DB_CACHE_DIR`.

### Pitfall 12: claims
"Only SCA scanner with EUVD" (blog, 2026-03-23) is no longer defensible (Holm Security, CIRCL Vulnerability-Lookup ingest EUVD; Dependency-Track/Trivy in progress). "CRA compliant", "powered by ENISA", ENISA/EU logo use are not allowed / risky.

---

## Code Examples

### Parse EUVD date
```ts
// "Sep 9, 2026, 1:00:31 PM" → "2026-09-09" (date only; EUVD gives no timezone → treat as UTC).
// Without the " UTC" suffix, V8 parses in the local TZ and "12:00:00 AM" shifts to the previous
// day east of UTC (verified: Europe/Berlin gave 2026-09-21 for "Sep 22, 2026, 12:00:00 AM").
export function parseEuvdDate(s: string | null | undefined): string | null {
  if (!s) return null;
  const d = new Date(s.replace(/,\s(\d{1,2}:)/, " $1") + " UTC");
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}
```

### Load EUVD KEV dump with fallback (sketch)
```ts
const KEV_DUMP_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump";
type KevSource = "cisa_kev" | "eukev_kev";
export interface ExploitedInfo { sources: KevSource[]; dateAdded: string; euvdId: string | null }

export async function loadExploited(): Promise<Map<string, ExploitedInfo>> {
  // 24h module cache like kev.ts; on EUVD failure fall back to loadKev() (CISA mirror)
  // mapping each CISA cveID → { sources: ["cisa_kev"], dateAdded, euvdId: null }
}
```

### Test pattern (existing conventions)
```ts
beforeEach(() => vi.resetModules());
afterEach(() => vi.unstubAllGlobals());
vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(fixture))));
```

---

## State of the Art

| Area | Status (Sept 2026) |
|---|---|
| EUVD | Operational since 13 May 2025 (NIS2 Art. 12(2)); ENISA CNA since Jan 2024, CVE Root since Nov 2025; API unauthenticated, no versioning |
| EU KEV | Confirmed exploitation against EU entities (EU CSIRTs Network, ENISA CTI, since 11 Sep 2026 also CRA reports via SRP `originSource`); 55 EU entries; published at `github.com/enisaeu/CNW/eukev` |
| EUVD exploited vs CISA KEV | EUVD 1,733 ⊇ CISA 1,721 (0 missing, 12 extra); `exploitedSince` = CISA `dateAdded` for 1,712/1,721 |
| CRA reporting | Art. 14 applies since 11 Sep 2026; SRP live, web-only, no API, EU Login + MFA, optional EUVD-ID field |
| CRA SBOM format | Annex I Part II(1): machine-readable, at least top-level deps; **no implementing act under Art. 13(24) found**; BSI TR-03183-2 most concrete reference |
| Grype DB | Schema v6, built daily, ~160 MB `.tar.zst` / ~2.2 GB SQLite, served via Cloudflare; no explicit DB licence (GHSA upstream CC-BY-4.0) |
| EUVD in vunnel | Issue #915 open; PR #1156 "Add ENISA EUVD provider" open, unmerged |
| Competitors | Holm Security, Greenbone (network VM) and CIRCL Vulnerability-Lookup use EUVD; Dependency-Track #4863 and Trivy #8958 open; none found for Grype, Snyk, OpenCVE |

---

## Open Questions

1. **Flag & default:** Should EUVD `kev/dump` be the default for everyone (recommended) or only under `--eu-sources`? — recommended: default, with CISA fallback.
2. **Mirror hosting:** Hetzner Object Storage vs nginx on the existing CAX11; who monitors the daily sync? — OPEN.
3. **Grype DB licence/attribution:** no explicit Anchore DB licence found; publish NOTICE with GHSA (CC-BY-4.0), NVD, CISA (CC0), FIRST EPSS, ENISA. — ASSUMED sufficient, confirm.
4. **Registry lookups in sovereign mode:** disable, or keep with "US endpoint" label? — OPEN.
5. **Dashboard (depwatch):** same enrichment via `@ottersight/scanner` — does the API worker pick up the new fields automatically? — OPEN (depwatch imports `loadKev`/`loadEuvdMapping` from scanner).
6. **CRA Art. 69(3)** (reporting for products placed on the market before 2027) — not verified.
7. **Does Grype JSON expose KEV/EPSS per match** from its own `kev`/`epss` providers? `types.ts` has `epss`, KEV not verified. — OPEN, check in Wave 0.

---

## Validation Architecture

### Test Framework
Vitest, existing patterns (`vi.hoisted`, `vi.stubGlobal('fetch')`, `vi.resetModules()` for module caches, promisify.custom for execFile).

### Requirements → Test Map
| Requirement | Test |
|---|---|
| EUVD KEV dump parsed (sources, dateAdded, euvdId) | `scanner/__tests__/euvd.test.ts` with fixture |
| Fallback to CISA mirror when EUVD fails; empty when both fail | `euvd.test.ts` / `kev.test.ts` |
| 204 / empty body tolerated | `euvd.test.ts` |
| Date parser (`MMM d, yyyy, h:mm:ss a` → ISO) | unit |
| Alias splitter (trailing `\n`, mixed order) | unit |
| `EnrichedVuln.exploitedSources/exploitedSince/cvss/epss` | `scanner/__tests__/enrich.test.ts` (moved) |
| EU-KEV-only CVE flagged (e.g. CVE-2015-7501) | enrich test |
| Dedup unchanged `(package, version, cveId)` | existing enrich tests |
| Renderers show EUVD-first, `EU KEV` vs `CISA KEV`, attribution | `render.test.ts`, `sarif.test.ts` |
| MCP scan output includes new fields | `mcp/__tests__` |
| Sovereign env passed to execFile (Phase 2) | `scan.test.ts` asserts `env` |

### Sampling Rate
Unit tests on every change; one manual live run against the real EUVD API per phase (`node packages/cli/dist/index.js scan .` on a fixture repo with lodash 4.17.20 + commons-collections 3.2.1).

### Wave 0 Gaps
- Fixtures: trimmed `kev/dump` JSON (incl. one `eukev_kev`-only entry), `enisaid` sample, 204 case.
- Check Grype JSON for per-match KEV/EPSS fields.
- `scanner/__tests__/enrich.test.ts` does not exist yet (enrich tests live in CLI).

---

## Sources

### Primary (HIGH confidence)
- Live EUVD API (curl, read-only, ~45 calls): `search`, `enisaid`, `advisory`, `last/exploited/criticalvulnerabilities`, `dump/cve-euvd-mapping`, `kev/dump`, `kevEntries`, `honeypotObservations`; apidoc bundle `euvd.enisa.europa.eu/static/js/main.*.js`
- Local Grype 0.118.0 / Syft 1.51.1: `grype db status|list|providers`, `grype config`, `syft config`
- https://grype.anchore.io/databases/v6/latest.json
- https://raw.githubusercontent.com/anchore/grype/main/grype/db/v6/distribution/client.go
- https://github.com/enisaeu/CNW/blob/main/eukev/README.md
- https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched
- https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_14.html · …Article_17.html · …Article_71.html · …Article_13.html
- https://www.enisa.europa.eu/about-enisa/legal-notice

### Secondary (MEDIUM confidence)
- https://www.vulncheck.com/blog/enisa-euvd
- https://github.com/cku-heise/euvd-api-doc
- https://oss.anchore.com/docs/architecture/grype-db/ · https://oss.anchore.com/docs/guides/vulnerability/database/
- https://github.com/anchore/vunnel/issues/915 · https://github.com/anchore/vunnel/pull/1156
- https://github.com/github/advisory-database/blob/main/LICENSE.md
- https://www.crowell.com/en/insights/client-alerts/its-live-the-cyber-resilience-act-reporting-is-mandatory-as-of-today-11-september-2026
- https://www.helpnetsecurity.com/2026/09/14/enisa-cra-single-reporting-platform/
- https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation
- https://www.enisa.europa.eu/publications/sbom-adoption-state-of-play-2026
- https://github.com/DependencyTrack/dependency-track/issues/4863 · https://github.com/aquasecurity/trivy/discussions/8958
- https://www.vulnerability-lookup.org/sources/ · https://gcve.eu/about/
- CSAF: https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json (200, 14 providers) · https://advisories.ncsc.nl/.well-known/csaf/provider-metadata.json (200)

### Context7
| Query | Result |
|---|---|
| `resolve-library-id "ENISA EUVD"`, `"EUVD API"` | **Not found** (no coverage) → web + live API used |
| `/anchore/grype` — offline db import, update-url, latest.json | db_import.go, db_list.go, db_status.go (HIGH) |
| `/anchore/syft` — network access at scan time | capabilities README, config wiki `check-for-app-update` |
| `vunnel`, `grype-db` | Not found / only `/anchore/grype` → web |
| `/cyclonedx/cyclonedx-go` — vulnerability source/refs/VEX | `Vulnerability` struct: `source`, `references`, `ratings`, `advisories`, `analysis` |
| `CSAF` | only `/gocsaf/csaf` (tooling: aggregator/downloader config), no OASIS spec |
| `SARIF` | `/microsoft/sarif-tools` (property bags), no spec entry |
| `/google/osv.dev` | schema (`aliases`, `upstream`); data sources contain no EU source |

## Metadata
- Research method: 3 parallel research agents (EUVD API · Grype DB/mirroring · CRA/EU sources/market), each required to use Context7 + WebSearch, consolidated here.
- Valid until: ~2026-12-23 for API facts (undocumented endpoints may change); re-verify `kev/dump`, vunnel #1156, Dependency-Track #4863 before each phase.
