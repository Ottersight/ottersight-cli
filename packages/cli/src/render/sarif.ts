import { formatExploited, DATA_ATTRIBUTION, type EnrichedVuln } from "@ottersight/scanner";

// SARIF 2.1.0 — consumed by GitHub Code Scanning, VS Code SARIF Viewer, etc.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

// GitHub derives the displayed severity from `security-severity` (CVSS-like 0.0–10.0).
const SECURITY_SEVERITY: Record<string, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
  negligible: "0.0",
  unknown: "0.0",
};

type SarifLevel = "error" | "warning" | "note";

function sarifLevel(severity: string): SarifLevel {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

function helpUri(id: string): string | undefined {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return undefined;
}

function message(v: EnrichedVuln): string {
  const parts = [`${v.packageName}@${v.packageVersion} is affected by ${v.cveId} (${v.severity}).`];
  if (v.euvdId) parts.push(`EUVD: ${v.euvdId}.`);
  if (v.exploitedSources.length > 0) {
    parts.push(`Known exploited (${formatExploited(v)}${v.exploitedSince ? `, since ${v.exploitedSince}` : ""}).`);
  }
  parts.push(v.fixVersion ? `Fixed in ${v.fixVersion}.` : "No fix available.");
  return parts.join(" ");
}

export function renderSarif(vulns: EnrichedVuln[], toolVersion: string): string {
  // One rule per vulnerability ID; severity of the first occurrence wins.
  const rules = new Map<string, object>();
  for (const v of vulns) {
    if (rules.has(v.cveId)) continue;
    const sev = v.severity.toLowerCase();
    const tags = ["security", "vulnerability", "dependency"];
    if (v.exploitedSources.length > 0) tags.push("kev");
    if (v.exploitedSources.includes("eukev_kev")) tags.push("eu-kev");
    rules.set(v.cveId, {
      id: v.cveId,
      name: v.cveId,
      shortDescription: { text: `${v.cveId} (${sev})` },
      fullDescription: { text: `Vulnerable dependency: ${v.cveId}` },
      ...(helpUri(v.cveId) && { helpUri: helpUri(v.cveId) }),
      help: { text: `See ${helpUri(v.cveId) ?? v.cveId} for details.` },
      defaultConfiguration: { level: sarifLevel(sev) },
      properties: {
        tags,
        "security-severity": SECURITY_SEVERITY[sev] ?? "0.0",
      },
    });
  }

  const results = vulns.map((v) => ({
    ruleId: v.cveId,
    level: sarifLevel(v.severity),
    message: { text: message(v) },
    locations: (v.locations ?? []).map((uri) => ({
      physicalLocation: {
        artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
        region: { startLine: 1 },
      },
    })),
    partialFingerprints: {
      "ottersight/v1": `${v.packageName}@${v.packageVersion}:${v.cveId}`,
    },
    properties: {
      packageName: v.packageName,
      packageVersion: v.packageVersion,
      severity: v.severity,
      fixVersion: v.fixVersion,
      euvdId: v.euvdId,
      inKev: v.inKev,
      exploitedSources: v.exploitedSources,
      exploitedSince: v.exploitedSince,
      cvss: v.cvss,
      epss: v.epss,
    },
  }));

  const log = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "OtterSight",
            version: toolVersion,
            informationUri: "https://github.com/Ottersight/ottersight-cli",
            rules: [...rules.values()],
          },
        },
        results,
        properties: { dataAttribution: DATA_ATTRIBUTION },
      },
    ],
  };

  return JSON.stringify(log, null, 2);
}
