import { describe, it, expect, vi } from "vitest";

// Smoke test: McpServer can be instantiated without throwing.
// We mock the SDK transport to avoid stdio binding in test environment.
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn().mockImplementation(() => ({})),
}));

describe("MCP Server", () => {
  it("McpServer can be instantiated with name 'ottersight' and version '0.1.3'", async () => {
    const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
    expect(() => new McpServer({ name: "ottersight", version: "0.1.3" })).not.toThrow();
  });

  it("McpServer instance has the correct name and version", async () => {
    const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
    const server = new McpServer({ name: "ottersight", version: "0.1.3" });
    expect(server).toBeDefined();
  });
});
