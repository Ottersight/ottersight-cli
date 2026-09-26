// Types
export type {
  SyftComponent,
  SyftOutput,
  GrypeMatch,
  GrypeOutput,
  ScanLocalInput,
  ScanMeta,
  ScanResult,
  ComponentInput,
  EnrichedVuln,
} from "./types.js";

// Scanner
export { scanLocal } from "./scan.js";

// Enrichment
export { loadKev, isKnownExploited } from "./kev.js";
export {
  loadEuvdMapping,
  lookupEuvd,
  loadExploited,
  getExploitedSource,
  lookupEuvdRecord,
  parseEuvdDate,
  splitEuvdList,
} from "./euvd.js";
export type { ExploitedInfo, KevSource, EuvdRecord, ExploitedSource, LoadExploitedOptions } from "./euvd.js";
export {
  enrichVulnerabilities,
  resolveCveId,
  formatExploited,
  formatEpss,
  DATA_ATTRIBUTION,
} from "./enrich.js";
export { loadCveAliases } from "./osv.js";
export type { LoadCveAliasesOptions } from "./osv.js";
export { mirrorUrls, planSources } from "./mirror.js";
export type { MirrorUrls, SourceOptions, SourcePlan } from "./mirror.js";
export { lookupLatestVersions } from "./registries.js";

// Logger (exposed for consumers who want structured logging)
export { log } from "./logger.js";
