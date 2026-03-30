# @ottersight/scanner

[![npm version](https://img.shields.io/npm/v/@ottersight/scanner)](https://www.npmjs.com/package/@ottersight/scanner)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/@ottersight/scanner)](https://nodejs.org)

Local Software Composition Analysis (SCA) scanner with SBOM generation, CVE detection, EUVD mapping, CISA KEV enrichment, and registry version tracking.

## What it does

- **SBOM generation** via [Syft](https://github.com/anchore/syft) — produces a complete Bill of Materials from any local directory
- **CVE scanning** via [Grype](https://github.com/anchore/grype) — matches components against the NVD, OSV, GitHub Advisory, and other vulnerability databases
- **CISA KEV enrichment** — flags vulnerabilities that are actively exploited (Known Exploited Vulnerabilities catalog)
- **EUVD mapping** — maps CVE identifiers to the EU Vulnerability Database IDs for compliance reporting
- **Registry version tracking** — queries npm, PyPI, crates.io, Go proxy, Maven Central, and other registries to identify outdated components

## Prerequisites

Syft and Grype must be installed and available on `PATH`. They are bundled automatically when using the Docker image.

**macOS (Homebrew):**

```bash
brew install anchore/grype/grype
brew install anchore/syft/syft
```

**Linux (curl):**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

Verify the installations:

```bash
syft --version
grype --version
```

## Installation

**Install the CLI globally:**

```bash
npm install -g @ottersight/cli
```

**Run without installing:**

```bash
npx @ottersight/cli scan .
```

**Use the library in your project:**

```bash
npm install @ottersight/scanner
```

## CLI Usage

The CLI is provided by the `@ottersight/cli` package. After installing globally:

```bash
# Scan the current directory
ottersight scan .

# Scan a specific path
ottersight scan /path/to/your/project

# Write a Markdown report to a file
ottersight scan . --output report.md

# Suppress progress spinners (useful in CI output capture)
ottersight scan . --quiet

# Show help
ottersight --help
ottersight scan --help
```

## Docker

Run the scanner without installing anything locally. Syft and Grype are bundled in the image:

```bash
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
```

Write a Markdown report from Docker:

```bash
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo --output /repo/report.md
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed successfully (vulnerabilities may be present) |
| 1    | Scan failed (Syft/Grype error, missing tools, invalid path) |

### Output Formats

**Terminal (default):** Colored table grouped by severity (CRITICAL → HIGH → MEDIUM → LOW) with columns: Package, Version, CVE, Severity, EUVD-ID, KEV flag, Fix Available. A summary line is always printed at the end.

**Markdown file (`--output`):** Same structure as the terminal table but without ANSI color codes. Written to the path provided. The file is overwritten on each run.

## Library Usage

Use `@ottersight/scanner` directly in TypeScript or JavaScript projects:

```typescript
import {
  scanLocal,
  loadKev,
  loadEuvdMapping,
  lookupLatestVersions,
  type SyftComponent,
  type GrypeMatch,
  type EnrichedVuln,
  type ScanResult,
} from "@ottersight/scanner";

// Run a full scan on a local directory
const result: ScanResult = await scanLocal({ path: "/path/to/project" });

const { sbom, grype, meta } = result;
console.log(`Found ${sbom.components?.length ?? 0} components`);
console.log(`Found ${grype.matches?.length ?? 0} vulnerabilities`);

// Load enrichment data
const [kevSet, euvdMap] = await Promise.all([
  loadKev(),
  loadEuvdMapping(),
]);

// Enrich a vulnerability
for (const match of grype.matches ?? []) {
  const cveId = match.vulnerability.id;
  const isExploited = kevSet.has(cveId);
  const euvdId = euvdMap.get(cveId);
  console.log(`${cveId}: KEV=${isExploited}, EUVD=${euvdId ?? "none"}`);
}

// Check latest versions for components
const versionMap = await lookupLatestVersions(
  sbom.components?.map((c) => ({
    id: c.id ?? c.name,
    name: c.name,
    version: c.version,
    ecosystem: c.purl?.match(/^pkg:([^/]+)\//)?.[1] ?? null,
  })) ?? []
);
```

## API

### `scanLocal(input: ScanLocalInput): Promise<ScanResult>`

Runs Syft and Grype on a local directory. Requires Syft and Grype to be installed.

```typescript
interface ScanLocalInput {
  path: string;           // Absolute or relative path to the directory to scan
}

interface ScanResult {
  sbom: SyftOutput;       // Raw Syft JSON output
  grype: GrypeOutput;     // Raw Grype JSON output
  meta: ScanMeta;         // Scan metadata (duration, manifests found, etc.)
}
```

### `loadKev(): Promise<Set<string>>`

Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog and returns a `Set<string>` of CVE IDs. Results are cached in-process for the lifetime of the process.

### `loadEuvdMapping(): Promise<Map<string, string>>`

Fetches the EU Vulnerability Database (EUVD) data and returns a `Map<string, string>` from CVE IDs to EUVD IDs. Results are cached in-process.

### `lookupLatestVersions(components: ComponentInput[]): Promise<Map<string, { latestVersion: string | null; isOutdated: boolean }>>`

Queries package registries (npm, PyPI, crates.io, Go proxy, Maven Central, RubyGems, Hex, NuGet, and others) to determine the latest stable version for each component.

```typescript
interface ComponentInput {
  id: string;             // Unique identifier for the component (used as map key)
  name: string;
  version: string | null;
  ecosystem: string | null;  // e.g. "npm", "pip", "cargo", "go", "maven"
}
```

### `isKnownExploited(cveId: string): Promise<boolean>`

Convenience function that loads the KEV catalog and checks a single CVE ID.

### `lookupEuvd(cveId: string): Promise<string | null>`

Convenience function that loads the EUVD mapping and returns the EUVD ID for a single CVE, or `null` if not found.

## Contributing

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes and add tests
4. Commit with a conventional commit message: `git commit -m "feat: add X"`
5. Push to your fork: `git push origin feat/your-feature`
6. Open a Pull Request

All contributions require tests. The project uses Vitest for unit and integration tests.

```bash
pnpm test        # Run all tests
pnpm build       # Build the package
pnpm typecheck   # Type-check without emitting
```

## License

[MIT](./LICENSE)

---

Powered by [OtterSight](https://ottersight.com) — Security Command Center for Indie Devs.
