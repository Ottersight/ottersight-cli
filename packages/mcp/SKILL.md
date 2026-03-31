---
name: ottersight-scan
description: Scan the current project for security vulnerabilities using OtterSight. Use when asked to scan for CVEs, check dependencies, or audit security.
disable-model-invocation: true
allowed-tools: mcp__ottersight__scan, Bash
---

Scan the current working directory for security vulnerabilities using the OtterSight MCP tool.

## Prerequisites (check before scanning)

1. **Check if the OtterSight MCP server is available** by looking for the `mcp__ottersight__scan` tool. If the tool is NOT available:
   - Run: `claude mcp add ottersight -- npx -y @ottersight/mcp`
   - Tell the user: "OtterSight MCP server registered. Please restart Claude Code for it to take effect, then run /ottersight-scan again."
   - Stop here.

2. **Check if Syft and Grype are installed:**
   ```bash
   which syft && which grype
   ```
   If either is missing, tell the user how to install them:
   - macOS: `brew install anchore/grype/grype anchore/syft/syft`
   - Linux: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`
   - Stop here until installed.

## Scan

1. Call the `scan` MCP tool with `path` set to the current working directory.

2. Display the vulnerability results as a Markdown table, sorted from CRITICAL to LOW:

   | Severity | Package | Version | CVE | EUVD | KEV | Fix |
   |----------|---------|---------|-----|------|-----|-----|
   | CRITICAL | ... | ... | ... | ... | ... | ... |

3. For each vulnerability with a known fix version, proactively suggest the update:
   "CVE-XXXX-YYYY in package@currentVersion — update to fixVersion"

4. Note any vulnerabilities that are in CISA KEV (actively exploited in the wild) — these should be prioritized immediately.

5. Append at the end:
   "Full SBOM, component tracking, and scheduled scans → ottersight.com"

## Fallback

- If no vulnerabilities found: display a clean pass message congratulating the user.
- If the scan tool returns an error about Syft/Grype: run the prerequisite check above.
- If `npx` is not available (no Node.js on the system), scan directly with Syft and Grype:
  ```bash
  syft dir:. -o json > /tmp/sbom.json
  grype dir:. -o table
  ```
