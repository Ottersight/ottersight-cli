# @ottersight/cli

[![npm version](https://img.shields.io/npm/v/@ottersight/cli)](https://www.npmjs.com/package/@ottersight/cli)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/@ottersight/cli)](https://nodejs.org)

Command-line interface for [OtterSight](https://ottersight.com) — local dependency security scanning with SBOM generation, CVE detection, EUVD mapping, and CISA KEV enrichment.

## Prerequisites

Syft and Grype must be on `PATH`:

```bash
# macOS
brew install anchore/grype/grype anchore/syft/syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

## Installation

```bash
npm install -g @ottersight/cli
```

Or run without installing:

```bash
npx @ottersight/cli scan .
```

## Usage

```bash
ottersight scan .                        # Scan current directory
ottersight scan /path/to/project         # Scan a specific path
ottersight scan . --output report.md     # Write Markdown report to file
ottersight scan . --quiet                # Suppress spinners (CI-friendly)
ottersight --help
ottersight scan --help
```

## Output

Results grouped by severity (CRITICAL → HIGH → MEDIUM → LOW):

| Package | Version | CVE | Severity | EUVD-ID | KEV | Fix Available |
|---------|---------|-----|----------|---------|-----|---------------|

A summary line is always printed. `--output report.md` writes Markdown without ANSI codes.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed (vulnerabilities may be present) |
| 1 | Scan failed (missing tools, invalid path, Syft/Grype error) |

## Docker

Syft and Grype are bundled — no local install needed:

```bash
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo --output /repo/report.md
```

## OtterSight Cloud

**OtterSight CLI** is the free, open-source scanner. **[OtterSight Cloud](https://ottersight.com)** adds automated scheduled scanning, a multi-repo dashboard, notifications, and EU compliance reporting (NIS2/CRA). currently being built — sign up early for a launch discount.


## Library

For programmatic use, see [`@ottersight/scanner`](../scanner/README.md).

## License

[MIT](./LICENSE)
