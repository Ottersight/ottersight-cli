# OtterSight — OSS Scanner

[![CI](https://github.com/Ottersight/ottersight-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Ottersight/ottersight-cli/actions/workflows/ci.yml)
[![npm @ottersight/scanner](https://img.shields.io/npm/v/@ottersight/scanner?label=%40ottersight%2Fscanner)](https://www.npmjs.com/package/@ottersight/scanner)
[![npm @ottersight/cli](https://img.shields.io/npm/v/@ottersight/cli?label=%40ottersight%2Fcli)](https://www.npmjs.com/package/@ottersight/cli)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

Local dependency security scanning for developers. Combines Syft (SBOM) + Grype (CVE) with CISA KEV enrichment and EU Vulnerability Database (EUVD) mapping.

```
$ ottersight scan .

Scanning /my-project...

CRITICAL (2)
  lodash    4.17.20  CVE-2021-23337  CRITICAL  EUVD-2021-12345  KEV ⚡  Fix: 4.17.21
  node      18.12.0  CVE-2023-30581  CRITICAL  —                —       Fix: 18.20.4

HIGH (5)
  ...

Summary: 127 components · 7 vulnerabilities · 2 actively exploited (KEV) · 3 EUVD entries
```

## Packages

| Package | Description |
|---------|-------------|
| [`@ottersight/scanner`](./packages/scanner) | Programmatic API — import in your TypeScript/JS project |
| [`@ottersight/cli`](./packages/cli) | CLI tool — `ottersight scan .` |

## Quick Start

```bash
# No install needed
npx @ottersight/cli scan .

# Install globally
npm install -g @ottersight/cli
ottersight scan .

# Docker (Syft + Grype bundled)
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
```

## Prerequisites

Syft and Grype must be on `PATH` (not needed with Docker):

```bash
# macOS
brew install anchore/grype/grype anchore/syft/syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

## What It Does

- **SBOM generation** — Syft produces a full Bill of Materials from any directory
- **CVE detection** — Grype matches against NVD, OSV, GitHub Advisory, and more
- **CISA KEV enrichment** — flags vulnerabilities actively exploited in the wild
- **EUVD mapping** — maps CVE IDs to EU Vulnerability Database IDs for NIS2/CRA compliance
- **Version tracking** — queries npm, PyPI, crates.io, Go proxy, Maven Central, and more

## Programmatic Usage

```typescript
import { scanLocal, loadKev, loadEuvdMapping } from "@ottersight/scanner";

const result = await scanLocal({ path: "/path/to/project" });
const [kevSet, euvdMap] = await Promise.all([loadKev(), loadEuvdMapping()]);

for (const match of result.grype.matches ?? []) {
  const cveId = match.vulnerability.id;
  console.log({ cve: cveId, exploited: kevSet.has(cveId), euvd: euvdMap.get(cveId) ?? null });
}
```

Full API: [`packages/scanner/README.md`](./packages/scanner/README.md)

## Development

```bash
pnpm install
pnpm build      # Build both packages
pnpm test       # Run tests
pnpm typecheck  # Type-check
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE) — Part of the [OtterSight](https://ottersight.com) open-core platform.
