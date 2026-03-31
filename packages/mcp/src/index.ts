import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { handleScan } from "./tools/scan.js";
import { handleCheckKev } from "./tools/check-kev.js";
import { handleLookupEuvd } from "./tools/lookup-euvd.js";

const server = new McpServer({ name: "ottersight", version: "0.1.3" });

server.registerTool(
  "scan",
  {
    description:
      "Scan a local directory for security vulnerabilities using Syft + Grype. Returns enriched CVE list with KEV and EUVD data.",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the directory to scan"),
    }),
  },
  async (args) => {
    try {
      return await handleScan(args);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `Scan failed: ${message}` }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  "check-kev",
  {
    description:
      "Check if a CVE ID is in the CISA Known Exploited Vulnerabilities (KEV) catalog.",
    inputSchema: z.object({
      cve_id: z.string().describe("CVE identifier, e.g. CVE-2021-44228"),
    }),
  },
  async (args) => {
    try {
      return await handleCheckKev(args);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `KEV lookup failed: ${message}` }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  "lookup-euvd",
  {
    description:
      "Look up the European Union Vulnerability Database (EUVD) ID for a given CVE.",
    inputSchema: z.object({
      cve_id: z.string().describe("CVE identifier, e.g. CVE-2021-44228"),
    }),
  },
  async (args) => {
    try {
      return await handleLookupEuvd(args);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `EUVD lookup failed: ${message}` }],
        isError: true,
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("MCP server fatal error:", err);
  process.exit(1);
});
