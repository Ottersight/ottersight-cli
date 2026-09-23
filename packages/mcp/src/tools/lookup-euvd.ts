import { loadEuvdMapping, lookupEuvdRecord } from "@ottersight/scanner";

export async function handleLookupEuvd(input: { cve_id: string }) {
  const euvdMap = await loadEuvdMapping();
  const euvdId = euvdMap.get(input.cve_id) ?? null;
  const record = euvdId ? await lookupEuvdRecord(euvdId) : null;

  let text: string;
  if (euvdId == null) {
    text = `No EUVD entry found for ${input.cve_id}.`;
  } else if (record == null) {
    text = `${input.cve_id} maps to EUVD ID: ${euvdId} (record details unavailable).`;
  } else {
    const lines = [`${input.cve_id} maps to EUVD ID: ${euvdId}`];
    if (record.baseScore != null) {
      lines.push(`CVSS ${record.baseScoreVersion ?? ""} ${record.baseScore} (assigned by ${record.assigner ?? "CNA"})`.replace("  ", " "));
    }
    if (record.epss != null) lines.push(`EPSS: ${(record.epss * 100).toFixed(1)}%`);
    if (record.exploitedSince) lines.push(`Known exploited since ${record.exploitedSince}`);
    if (record.aliases.length > 0) lines.push(`Aliases: ${record.aliases.join(", ")}`);
    if (record.description) lines.push("", record.description);
    lines.push("", "Source: ENISA EU Vulnerability Database (EUVD).");
    text = lines.join("\n");
  }

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      cveId: input.cve_id,
      euvdId,
      record,
    },
  };
}
