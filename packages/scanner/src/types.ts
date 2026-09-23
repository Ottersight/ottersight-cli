// ── Syft types ──

export interface SyftComponent {
  type: string;
  name: string;
  version: string;
  purl?: string;
  licenses?: Array<{ license: { id?: string; name?: string } }>;
}

export interface SyftOutput {
  components?: SyftComponent[];
}

// ── Grype types ──

export interface GrypeMatch {
  vulnerability: {
    id: string;
    severity: string;
    cvss?: Array<{ metrics?: { baseScore?: number }; version?: string }>;
    dataSource?: string;
    fix?: { versions?: string[]; state?: string };
    description?: string;
    epss?: Array<{ cve?: string; epss?: number; percentile?: number; date?: string }>;
  };
  artifact: {
    name: string;
    version: string;
    purl?: string;
    locations?: Array<{ path: string }>;
  };
  relatedVulnerabilities?: Array<{
    id: string;
    severity: string;
    cvss?: Array<{ metrics?: { baseScore?: number }; version?: string }>;
    description?: string;
  }>;
}

export interface GrypeOutput {
  matches?: GrypeMatch[];
}

// ── Scan input/output ──

export interface ScanLocalInput {
  path: string;
  timeout?: number;
  /** Keep Syft/Grype off US endpoints at scan time: no app-update checks, no external sources */
  euSources?: boolean;
  /** Grype DB listing base URL (e.g. an EU mirror; Grype appends /v6/latest.json). Default: Anchore */
  grypeDbUrl?: string;
}

export interface ScanMeta {
  cloneSuccess: boolean;
  syftExitCode: number;
  grypeExitCode: number;
  manifestsFound: string[];
  scannerVersion?: string;
  grypeVersion?: string;
  scannedAt?: string;
}

export interface ScanResult {
  commitSha: string;
  sbom: SyftOutput;
  grype: GrypeOutput;
  meta: ScanMeta;
}

// ── Registry types ──

export interface ComponentInput {
  id: string;
  name: string;
  version: string;
  ecosystem: string | null;
}

// ── CLI render layer ──

export interface EnrichedVuln {
  packageName: string;
  packageVersion: string;
  cveId: string;
  /** CVE used for EUVD/KEV enrichment when `cveId` is not a CVE (Grype related record, else OSV alias); null if none */
  aliasCveId?: string | null;
  severity: string;
  euvdId: string | null;
  /** @deprecated Use `exploitedSources`. True when listed in any KEV catalogue (CISA or EU). */
  inKev: boolean;
  /** KEV catalogues listing this CVE: "eukev_kev" (ENISA EU KEV), "cisa_kev". Empty = not known exploited. */
  exploitedSources: Array<"cisa_kev" | "eukev_kev">;
  /** ISO date the CVE was first added to a KEV catalogue (EUVD `dateAdded`); null if unknown */
  exploitedSince: string | null;
  /** Highest-version CVSS base score from Grype (advisory, else related CVE record); null if none */
  cvss: number | null;
  /** FIRST EPSS probability 0–1 from Grype; null if none */
  epss: number | null;
  fixVersion: string | null;
  /** Manifest/lockfile paths (relative to scan root) where the package was found */
  locations?: string[];
}
