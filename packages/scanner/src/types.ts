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
    epss?: Array<{ cve?: string; epss?: number }>;
  };
  artifact: {
    name: string;
    version: string;
    purl?: string;
  };
  relatedVulnerabilities?: Array<{
    id: string;
    severity: string;
    cvss?: Array<{ metrics?: { baseScore?: number } }>;
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
  severity: string;
  euvdId: string | null;
  inKev: boolean;
  fixVersion: string | null;
}
