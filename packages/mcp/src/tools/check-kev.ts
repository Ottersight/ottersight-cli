import { loadKev } from "@ottersight/scanner";

export async function handleCheckKev(input: { cve_id: string }) {
  const kevSet = await loadKev();
  const inKev = kevSet.has(input.cve_id);

  const text = inKev
    ? `${input.cve_id} is in CISA KEV -- actively exploited in the wild.`
    : `${input.cve_id} is NOT in CISA KEV.`;

  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      cveId: input.cve_id,
      inKev,
    },
  };
}
