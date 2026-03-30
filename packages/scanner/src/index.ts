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
export { loadEuvdMapping, lookupEuvd } from "./euvd.js";
export { lookupLatestVersions } from "./registries.js";

// Logger (exposed for consumers who want structured logging)
export { log } from "./logger.js";
