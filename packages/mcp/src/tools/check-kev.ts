import { loadExploited, formatExploited } from "@ottersight/scanner";

export async function handleCheckKev(input: { cve_id: string }) {
  const exploited = await loadExploited();
  const entry = exploited.get(input.cve_id);
  const sources = entry?.sources ?? [];
  const label = formatExploited({ exploitedSources: sources });

  const text = entry
    ? `${input.cve_id} is known exploited: listed in ${label}${entry.dateAdded ? ` since ${entry.dateAdded}` : ""}${entry.euvdId ? ` (${entry.euvdId})` : ""}. Source: ENISA EUVD.`
    : `${input.cve_id} is NOT in EU KEV or CISA KEV.`;

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      cveId: input.cve_id,
      inKev: entry !== undefined,
      exploitedSources: sources,
      exploitedSince: entry?.dateAdded ?? null,
      euvdId: entry?.euvdId ?? null,
    },
  };
}
