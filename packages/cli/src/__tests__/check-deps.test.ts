import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock which before importing check-deps
vi.mock("which", () => ({
  default: vi.fn(),
}));

import whichMock from "which";
import { checkDependencies } from "../check-deps.js";

const mockedWhich = vi.mocked(whichMock);

describe("checkDependencies", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(process, "exit").mockImplementation((() => {}) as () => never);
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("succeeds when syft and grype are found", async () => {
    mockedWhich.mockResolvedValue("/usr/local/bin/syft" as never);
    await checkDependencies();
    expect(process.exit).not.toHaveBeenCalled();
  });

  it("exits with error when syft missing", async () => {
    mockedWhich.mockImplementation(async (bin: string) => {
      if (bin === "syft") return null as never;
      return `/usr/local/bin/${bin}` as never;
    });
    await checkDependencies();
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("shows install instructions for missing tools", async () => {
    mockedWhich.mockImplementation(async (bin: string) => {
      if (bin === "grype") return null as never;
      return `/usr/local/bin/${bin}` as never;
    });
    await checkDependencies();
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining("grype not found")
    );
  });
});
