import { Command, Option } from "commander";
import { scanCommand } from "./commands/scan.js";

// Injected at build time by tsup (see tsup.config.ts)
declare const __OTTERSIGHT_VERSION__: string;

const program = new Command();

program
  .name("ottersight")
  .description("Local SCA scanner — SBOM + CVE + EUVD + KEV enrichment")
  .version(__OTTERSIGHT_VERSION__);

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

program
  .command("scan")
  .description("Scan a directory for vulnerabilities")
  .argument("<path>", "directory to scan (use . for current directory)")
  .addOption(
    new Option("-f, --format <format>", "stdout output format")
      .choices(["table", "sarif"])
      .default("table"),
  )
  .option("-o, --output <file>", "write Markdown report to file")
  .option("-i, --ignore <id>", "ignore a vulnerability by CVE/GHSA ID (repeatable)", collect, [])
  .option("-q, --quiet", "suppress progress spinners")
  .action(async (scanPath: string, options: { format: "table" | "sarif"; output?: string; ignore: string[]; quiet?: boolean }) => {
    await scanCommand(scanPath, { ...options, version: __OTTERSIGHT_VERSION__ });
  });

program.addHelpText("after", `
Examples:
  $ ottersight scan .                            Scan current directory
  $ ottersight scan /path/to/repo                Scan specific directory
  $ ottersight scan . --output report.md         Write Markdown report to file
  $ ottersight scan . --format sarif > out.sarif SARIF for GitHub Code Scanning
  $ ottersight scan . --ignore CVE-2021-23337    Suppress a specific vulnerability
  $ ottersight scan . --quiet                    Suppress progress output
  $ docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
`);

program.parseAsync();
