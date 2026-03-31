import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { log } from "./logger.js";
import type { ScanLocalInput, ScanResult, SyftOutput, GrypeOutput, ScanMeta } from "./types.js";

const execFileAsync = promisify(execFile);

export async function scanLocal(input: ScanLocalInput): Promise<ScanResult> {
  const timeout = input.timeout ?? 300_000;
  const maxBuffer = 100 * 1024 * 1024; // 100 MB

  // Attempt to get commit SHA if this is a git repo
  let commitSha = "";
  try {
    const { stdout } = await execFileAsync("git", ["-C", input.path, "rev-parse", "--short", "HEAD"], { timeout: 5_000 });
    commitSha = stdout.trim();
  } catch {
    // Not a git repo or git not installed — acceptable
  }

  // Run Syft for SBOM generation
  let sbom: SyftOutput = {};
  let syftExitCode = 1;
  try {
    const { stdout } = await execFileAsync("syft", [
      input.path, "-o", "cyclonedx-json", "--quiet",
    ], { timeout, maxBuffer });
    sbom = JSON.parse(stdout);
    syftExitCode = 0;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    const msg = err instanceof Error ? err.message : String(err);
    log.error("Syft failed", { path: input.path, error: msg, stderr });
    throw new Error(stderr ? `Syft scan failed: ${stderr}` : `Syft scan failed: ${msg}`);
  }

  // Run Grype for vulnerability analysis
  let grype: GrypeOutput = {};
  let grypeExitCode = 1;
  try {
    const { stdout } = await execFileAsync("grype", [
      `dir:${input.path}`, "-o", "json", "--quiet",
    ], { timeout, maxBuffer });
    grype = JSON.parse(stdout);
    grypeExitCode = 0;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    const msg = err instanceof Error ? err.message : String(err);
    log.error("Grype failed", { path: input.path, error: msg, stderr });
    throw new Error(stderr ? `Grype scan failed: ${stderr}` : `Grype scan failed: ${msg}`);
  }

  const meta: ScanMeta = {
    cloneSuccess: true, // N/A for local scan — always true
    syftExitCode,
    grypeExitCode,
    manifestsFound: [],
    scannedAt: new Date().toISOString(),
  };

  return { commitSha, sbom, grype, meta };
}
