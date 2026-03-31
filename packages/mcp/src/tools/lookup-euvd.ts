import { loadEuvdMapping } from "@ottersight/scanner";

export async function handleLookupEuvd(input: { cve_id: string }) {
  const euvdMap = await loadEuvdMapping();
  const euvdId = euvdMap.get(input.cve_id) ?? null;

  const text = euvdId != null
    ? `${input.cve_id} maps to EUVD ID: ${euvdId}`
    : `No EUVD entry found for ${input.cve_id}.`;

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      cveId: input.cve_id,
      euvdId,
    },
  };
}
