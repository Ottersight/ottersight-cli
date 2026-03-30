import { describe, it, expect, vi, beforeEach } from "vitest";

// vi.mock is hoisted — use vi.hoisted() so mockExecFileAsync is available in the factory
const { mockExecFileAsync } = vi.hoisted(() => {
  return { mockExecFileAsync: vi.fn() };
});

vi.mock("node:child_process", () => {
  const execFile = vi.fn();
  // Attach the custom promisify symbol so promisify() returns our mock directly
  (execFile as any)[Symbol.for("nodejs.util.promisify.custom")] = mockExecFileAsync;
  return { execFile };
});

import { scanLocal } from "../scan.js";

const MOCK_SYFT_OUTPUT = JSON.stringify({
  components: [{ type: "library", name: "lodash", version: "4.17.21" }],
});

const MOCK_GRYPE_OUTPUT = JSON.stringify({
  matches: [
    {
      vulnerability: { id: "CVE-2021-23337", severity: "High" },
      artifact: { name: "lodash", version: "4.17.21" },
    },
  ],
});

function setupMock(opts: { gitFails?: boolean; syftFails?: boolean }) {
  mockExecFileAsync.mockImplementation(async (cmd: string, _args: string[]) => {
    if (cmd === "git") {
      if (opts.gitFails) throw new Error("not a git repo");
      return { stdout: "abc1234\n", stderr: "" };
    }
    if (cmd === "syft") {
      if (opts.syftFails) throw new Error("syft not found");
      return { stdout: MOCK_SYFT_OUTPUT, stderr: "" };
    }
    if (cmd === "grype") {
      return { stdout: MOCK_GRYPE_OUTPUT, stderr: "" };
    }
    throw new Error(`unexpected command: ${cmd}`);
  });
}

describe("scanLocal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns ScanResult with sbom and grype populated (mock execFile)", async () => {
    setupMock({});
    const result = await scanLocal({ path: "/tmp/test-repo" });

    expect(result.sbom.components).toHaveLength(1);
    expect(result.sbom.components![0].name).toBe("lodash");
    expect(result.grype.matches).toHaveLength(1);
    expect(result.grype.matches![0].vulnerability.id).toBe("CVE-2021-23337");
    expect(result.meta.cloneSuccess).toBe(true);
    expect(result.meta.syftExitCode).toBe(0);
    expect(result.meta.grypeExitCode).toBe(0);
  });

  it("throws when Syft command fails (mock execFile throws)", async () => {
    setupMock({ syftFails: true });
    await expect(scanLocal({ path: "/tmp/test-repo" })).rejects.toThrow("Syft scan failed");
  });

  it("sets commitSha from git rev-parse when .git is present", async () => {
    setupMock({});
    const result = await scanLocal({ path: "/tmp/test-repo" });
    expect(result.commitSha).toBe("abc1234");
  });

  it("sets empty commitSha when path has no .git directory", async () => {
    setupMock({ gitFails: true });
    const result = await scanLocal({ path: "/tmp/no-git" });
    expect(result.commitSha).toBe("");
  });
});
