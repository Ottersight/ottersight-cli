import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { log } from "./logger.js";
import { mirrorUrls } from "./mirror.js";
import type { ScanLocalInput, ScanResult, SyftOutput, GrypeOutput, ScanMeta } from "./types.js";

const execFileAsync = promisify(execFile);

/** Environment for Syft/Grype. Env names verified against grype 0.118.0 / syft (`<tool> config`). */
export function toolEnv(input: Pick<ScanLocalInput, "euSources" | "grypeDbUrl" | "mirrorUrl">): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  const grypeDbUrl = resolveGrypeDbUrl(input);
  if (input.euSources) {
    env.SYFT_CHECK_FOR_APP_UPDATE = "false";
    env.GRYPE_CHECK_FOR_APP_UPDATE = "false";
    env.GRYPE_EXTERNAL_SOURCES_ENABLE = "false";
  }
  if (grypeDbUrl) {
    env.GRYPE_DB_UPDATE_URL = grypeDbUrl;
    // Fail loudly when the mirror is unreachable instead of scanning with an outdated DB.
    env.GRYPE_DB_REQUIRE_UPDATE_CHECK = "true";
    // Grype skips the update check for 2 h after the last one, so a cached DB from another
    // URL would be used silently. Check the mirror on every run (only a small listing file).
    env.GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY = "0s";
  }
  return env;
}

/** Explicit Grype DB URL, else the mirror's, else undefined (Grype's default, Anchore). */
export function resolveGrypeDbUrl(input: Pick<ScanLocalInput, "grypeDbUrl" | "mirrorUrl">): string | undefined {
  return input.grypeDbUrl ?? (input.mirrorUrl ? mirrorUrls(input.mirrorUrl).grypeDb : undefined);
}

export async function scanLocal(input: ScanLocalInput): Promise<ScanResult> {
  const timeout = input.timeout ?? 300_000;
  const maxBuffer = 100 * 1024 * 1024; // 100 MB
  const env = toolEnv(input);

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
    ], { timeout, maxBuffer, env });
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
    ], { timeout, maxBuffer, env });
    grype = JSON.parse(stdout);
    grypeExitCode = 0;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    const msg = err instanceof Error ? err.message : String(err);
    log.error("Grype failed", { path: input.path, error: msg, stderr });
    // With --quiet Grype prints nothing, so a mirror problem would otherwise show as a bare "Command failed".
    const grypeDbUrl = resolveGrypeDbUrl(input);
    const hint = grypeDbUrl
      ? ` (check that the Grype DB mirror ${grypeDbUrl} is reachable and serves /v6/latest.json)`
      : "";
    throw new Error((stderr ? `Grype scan failed: ${stderr}` : `Grype scan failed: ${msg}`) + hint);
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
