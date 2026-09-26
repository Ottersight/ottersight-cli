import { resolve } from "node:path";
import { writeFile, stat } from "node:fs/promises";
import ora from "ora";
import chalk from "chalk";
import {
  scanLocal,
  loadExploited,
  getExploitedSource,
  loadEuvdMapping,
  loadCveAliases,
  planSources,
  enrichVulnerabilities,
  type GrypeMatch,
} from "@ottersight/scanner";
import { checkDependencies } from "../check-deps.js";
import { renderTerminalTable, renderSummaryLine, renderAttribution } from "../render/terminal.js";
import { renderMarkdown } from "../render/markdown.js";
import { renderSarif } from "../render/sarif.js";
import { renderJson } from "../render/json.js";
import { failingFindings, type FailOnLevel } from "../fail-on.js";
import { filterIgnored } from "../ignore.js";

const EXPLOITED_SOURCE_NOTICE = {
  "euvd-stale": "Note: ENISA EUVD was unreachable; known-exploited data is from an earlier EUVD download.",
  "cisa-fallback": "Note: ENISA EUVD was unreachable; showing CISA KEV only (EU KEV is missing).",
  none: "Note: known-exploited data (EUVD, CISA KEV) could not be loaded; exploitation flags are missing.",
} as const;

const EU_SOURCES_NO_MIRROR_NOTICE =
  "Note: --eu-sources without --mirror or --grype-db-url: the Grype vulnerability DB is still downloaded from Anchore (grype.anchore.io, US), and GHSA-only findings are not resolved to CVEs.";

interface ScanOptions {
  format?: "table" | "sarif" | "json";
  output?: string;
  ignore?: string[];
  quiet?: boolean;
  /** Resolve GHSA-only findings to CVEs (default true; via the mirror, else OSV.dev; off with euSources and no mirror) */
  osv?: boolean;
  /** No US endpoints for enrichment (EUVD only) and no Syft/Grype update checks */
  euSources?: boolean;
  /** Grype DB listing base URL (EU mirror) */
  grypeDbUrl?: string;
  /** OtterSight data mirror base URL: Grype DB, GHSA → CVE map and CISA KEV instead of US endpoints */
  mirrorUrl?: string;
  /** Exit 1 when a finding reaches this severity (or is known exploited, "kev") */
  failOn?: FailOnLevel;
  version?: string;
}

export async function scanCommand(scanPath: string, options: ScanOptions): Promise<void> {
  // Suppress scanner info/warn logs in CLI mode — only show errors
  process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? "error";

  const resolvedPath = resolve(scanPath);

  // Verify path exists and is a directory
  try {
    const st = await stat(resolvedPath);
    if (!st.isDirectory()) {
      console.error(chalk.red(`Error: ${resolvedPath} is not a directory`));
      process.exit(1);
    }
  } catch {
    console.error(chalk.red(`Error: ${resolvedPath} does not exist`));
    process.exit(1);
  }

  // Check for Syft + Grype on PATH
  await checkDependencies();

  const quiet = options.quiet ?? false;
  const euSources = options.euSources ?? false;

  // Step 1: Run scan (Syft SBOM + Grype vulnerability analysis)
  const scanSpinner = quiet ? null : ora("Generating SBOM with Syft...").start();
  let scanResult;
  try {
    scanResult = await scanLocal({ path: resolvedPath, euSources, grypeDbUrl: options.grypeDbUrl, mirrorUrl: options.mirrorUrl });
    scanSpinner?.succeed("SBOM generated, vulnerabilities analyzed");
  } catch (err) {
    scanSpinner?.fail("Scan failed");
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exit(1);
  }

  const allMatches: GrypeMatch[] = scanResult.grype.matches ?? [];
  const matches = filterIgnored(allMatches, options.ignore ?? []);

  // Step 2: Enrichment (EUVD KEV dump incl. EU KEV, EUVD IDs — graceful degradation on network failure)
  const enrichSpinner = quiet ? null : ora("Enriching with EUVD (EU + CISA KEV) data...").start();

  const sources = planSources({ euSources, mirrorUrl: options.mirrorUrl, osv: options.osv });
  const [exploited, euvdMap, cveAliases] = await Promise.all([
    loadExploited(sources.exploited),
    loadEuvdMapping(),
    sources.aliases ? loadCveAliases(matches, sources.aliases) : undefined,
  ]);

  enrichSpinner?.succeed("Enrichment complete");
  const exploitedSource = getExploitedSource();

  // Build enriched vulns from GrypeMatch[] + KEV/EUVD data
  const vulns = enrichVulnerabilities(matches, exploited, euvdMap, cveAliases);

  // Count ignored findings with the same dedup key as enrichVulnerabilities()
  const kept = new Set(matches);
  const ignoredCount = new Set(
    allMatches
      .filter((m) => !kept.has(m))
      .map((m) => `${m.artifact.name}@${m.artifact.version}:${m.vulnerability.id}`),
  ).size;
  const machine = options.format === "sarif" || options.format === "json";
  const status = machine ? console.error : console.log;

  // Step 3: stdout output. In SARIF/JSON mode stdout carries only the document,
  // so human-readable status goes to stderr.
  if (options.format === "sarif") {
    console.log(renderSarif(vulns, options.version ?? "0.0.0", { exploitedSource }));
    status(chalk.bold(renderSummaryLine(vulns)));
  } else if (options.format === "json") {
    console.log(renderJson(vulns, {
      version: options.version ?? "0.0.0",
      scannedPath: resolvedPath,
      commitSha: scanResult.commitSha,
      exploitedSource,
      euSources,
      ignored: ignoredCount,
    }));
    status(chalk.bold(renderSummaryLine(vulns)));
  } else {
    console.log(""); // blank line before table
    if (vulns.length > 0) {
      console.log(renderTerminalTable(vulns));
    }
    console.log(chalk.bold(renderSummaryLine(vulns)));
    if (vulns.length > 0) console.log(chalk.gray(renderAttribution()));

    if (scanResult.commitSha) {
      console.log(chalk.gray(`Commit: ${scanResult.commitSha}`));
    }
  }
  if (exploitedSource !== "euvd") {
    status(chalk.yellow(EXPLOITED_SOURCE_NOTICE[exploitedSource]));
  }
  if (euSources && !options.grypeDbUrl && !options.mirrorUrl) {
    status(chalk.yellow(EU_SOURCES_NO_MIRROR_NOTICE));
  }
  if (ignoredCount > 0) {
    status(chalk.gray(`Ignored: ${ignoredCount} finding(s) via --ignore`));
  }

  // Step 4: Markdown output to file (per D-03: file only, no stdout markdown)
  if (options.output) {
    const md = renderMarkdown(vulns);
    await writeFile(options.output, md, "utf-8");
    status(chalk.green(`\nReport written to ${options.output}`));
  }

  // Exit code 0 = scan complete, even with findings (D-03), unless --fail-on is met.
  // No process.exit(): it cuts off stdout writes still pending on a pipe (SARIF stopped at 64 KiB).
  const failing = options.failOn ? failingFindings(vulns, options.failOn) : [];
  if (failing.length > 0) {
    const what = options.failOn === "kev" ? "known exploited" : `${options.failOn} or higher`;
    status(chalk.red(`Failing: ${failing.length} finding(s) ${what} (--fail-on ${options.failOn})`));
  }
  process.exitCode = failing.length > 0 ? 1 : 0;
}
