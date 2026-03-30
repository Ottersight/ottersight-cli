import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";

const program = new Command();

program
  .name("ottersight")
  .description("Local SCA scanner — SBOM + CVE + EUVD + KEV enrichment")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a directory for vulnerabilities")
  .argument("<path>", "directory to scan (use . for current directory)")
  .option("-o, --output <file>", "write Markdown report to file")
  .option("-q, --quiet", "suppress progress spinners")
  .action(async (scanPath: string, options: { output?: string; quiet?: boolean }) => {
    await scanCommand(scanPath, options);
  });

program.addHelpText("after", `
Examples:
  $ ottersight scan .                     Scan current directory
  $ ottersight scan /path/to/repo         Scan specific directory
  $ ottersight scan . --output report.md  Write Markdown report to file
  $ ottersight scan . --quiet             Suppress progress output
  $ docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
`);

program.parseAsync();
