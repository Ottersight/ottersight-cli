import { resolve } from "node:path";
import { writeFile, stat } from "node:fs/promises";
import ora from "ora";
import chalk from "chalk";
import {
  scanLocal,
  loadKev,
  loadEuvdMapping,
  type GrypeMatch,
} from "@ottersight/scanner";
import { checkDependencies } from "../check-deps.js";
import { renderTerminalTable, renderSummaryLine } from "../render/terminal.js";
import { renderMarkdown } from "../render/markdown.js";
import { enrichVulnerabilities } from "../enrich.js";

interface ScanOptions {
  output?: string;
  quiet?: boolean;
}

export async function scanCommand(scanPath: string, options: ScanOptions): Promise<void> {
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

  const matches: GrypeMatch[] = scanResult.grype.matches ?? [];

  // Step 2: Enrichment (KEV, EUVD — all optional/graceful degradation on network failure)
  const enrichSpinner = quiet ? null : ora("Enriching with KEV and EUVD data...").start();

  const [kevSet, euvdMap] = await Promise.all([
    loadKev(),
    loadEuvdMapping(),
  ]);

  enrichSpinner?.succeed("Enrichment complete");

  // Build enriched vulns from GrypeMatch[] + KEV/EUVD data
  const vulns = enrichVulnerabilities(matches, kevSet, euvdMap);

  // Step 3: Terminal output
  console.log(""); // blank line before table
  if (vulns.length > 0) {
    console.log(renderTerminalTable(vulns));
  }
  console.log(chalk.bold(renderSummaryLine(vulns)));

  if (scanResult.commitSha) {
    console.log(chalk.gray(`Commit: ${scanResult.commitSha}`));
  }

  // Step 4: Markdown output to file (per D-03: file only, no stdout markdown)
  if (options.output) {
    const md = renderMarkdown(vulns);
    await writeFile(options.output, md, "utf-8");
    console.log(chalk.green(`\nReport written to ${options.output}`));
  }

  // Exit code 0 = scan complete (even with vulnerabilities found). Per D-03.
  process.exit(0);
}
