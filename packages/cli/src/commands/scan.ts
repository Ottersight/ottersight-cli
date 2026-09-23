import { resolve } from "node:path";
import { writeFile, stat } from "node:fs/promises";
import ora from "ora";
import chalk from "chalk";
import {
  scanLocal,
  loadExploited,
  loadEuvdMapping,
  enrichVulnerabilities,
  type GrypeMatch,
} from "@ottersight/scanner";
import { checkDependencies } from "../check-deps.js";
import { renderTerminalTable, renderSummaryLine, renderAttribution } from "../render/terminal.js";
import { renderMarkdown } from "../render/markdown.js";
import { renderSarif } from "../render/sarif.js";
import { filterIgnored } from "../ignore.js";

interface ScanOptions {
  format?: "table" | "sarif";
  output?: string;
  ignore?: string[];
  quiet?: boolean;
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

  // Step 1: Run scan (Syft SBOM + Grype vulnerability analysis)
  const scanSpinner = quiet ? null : ora("Generating SBOM with Syft...").start();
  let scanResult;
  try {
    scanResult = await scanLocal({ path: resolvedPath });
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

  const [exploited, euvdMap] = await Promise.all([
    loadExploited(),
    loadEuvdMapping(),
  ]);

  enrichSpinner?.succeed("Enrichment complete");

  // Build enriched vulns from GrypeMatch[] + KEV/EUVD data
  const vulns = enrichVulnerabilities(matches, exploited, euvdMap);

  // Count ignored findings with the same dedup key as enrichVulnerabilities()
  const kept = new Set(matches);
  const ignoredCount = new Set(
    allMatches
      .filter((m) => !kept.has(m))
      .map((m) => `${m.artifact.name}@${m.artifact.version}:${m.vulnerability.id}`),
  ).size;
  const sarif = options.format === "sarif";
  const status = sarif ? console.error : console.log;

  // Step 3: stdout output. In SARIF mode stdout carries only the JSON document,
  // so human-readable status goes to stderr.
  if (sarif) {
    console.log(renderSarif(vulns, options.version ?? "0.0.0"));
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
  if (ignoredCount > 0) {
    status(chalk.gray(`Ignored: ${ignoredCount} finding(s) via --ignore`));
  }

  // Step 4: Markdown output to file (per D-03: file only, no stdout markdown)
  if (options.output) {
    const md = renderMarkdown(vulns);
    await writeFile(options.output, md, "utf-8");
    status(chalk.green(`\nReport written to ${options.output}`));
  }

  // Exit code 0 = scan complete (even with vulnerabilities found). Per D-03.
  process.exit(0);
}
