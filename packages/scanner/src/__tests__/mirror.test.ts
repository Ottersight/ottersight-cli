import { describe, it, expect } from "vitest";
import { mirrorUrls, planSources } from "../mirror.js";

describe("mirrorUrls", () => {
  it("derives every source URL from the base, ignoring trailing slashes", () => {
    expect(mirrorUrls("https://mirror.example.eu/")).toEqual({
      grypeDb: "https://mirror.example.eu/grype",
      osvAliases: "https://mirror.example.eu/osv/ghsa-cve.json",
      kev: "https://mirror.example.eu/kev/known_exploited_vulnerabilities.json",
    });
  });
});

describe("planSources", () => {
  const MIRROR = "https://mirror.example.eu";

  it("default: CISA cross-check from GitHub, aliases from OSV.dev", () => {
    expect(planSources({})).toEqual({ exploited: { euOnly: false, kevUrl: undefined }, aliases: {} });
  });

  it("euSources without a mirror: EUVD only, no alias resolution", () => {
    expect(planSources({ euSources: true })).toEqual({ exploited: { euOnly: true, kevUrl: undefined }, aliases: null });
  });

  it("euSources with a mirror: CISA KEV and aliases come from the mirror", () => {
    expect(planSources({ euSources: true, mirrorUrl: MIRROR })).toEqual({
      exploited: { euOnly: false, kevUrl: `${MIRROR}/kev/known_exploited_vulnerabilities.json` },
      aliases: { aliasMapUrl: `${MIRROR}/osv/ghsa-cve.json` },
    });
  });

  it("osv: false turns alias resolution off, even with a mirror", () => {
    expect(planSources({ mirrorUrl: MIRROR, osv: false }).aliases).toBeNull();
  });
});
