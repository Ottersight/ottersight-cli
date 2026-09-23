# EUVD-First & Digital Sovereignty — Plan

**Created:** 2026-09-23 · **Status:** Phase 0 done · Phase 1 done (except depwatch follow-up) · Phase 2 next
**Research:** [`tasks/euvd-sovereignty/RESEARCH.md`](euvd-sovereignty/RESEARCH.md) (GSD phase-research format)
**Goal:** EUVD becomes OtterSight's primary enrichment and exploitation source; the runtime can run without US endpoints; every claim is verifiable.

GSD mapping: each phase below is meant to become one GSD phase (`/gsd-phase` add → `/gsd-plan-phase`). Copy the research into `.planning/phases/NN-<slug>/NN-RESEARCH.md` when the phase is created.

---

## Phase 0 — Fix claims now (copy only, no code)

Why first: research found claims that are no longer true or are legally risky.

- [x] Blog `2026-03-23-euvd-explained`: remove "the only SCA scanner that directly integrates EUVD" (Holm Security, CIRCL Vulnerability-Lookup already ingest EUVD; Dependency-Track #4863 / Trivy #8958 in progress)
- [x] Homepage (depwatch PR #3), feature F03 "CVSS + EPSS + CISA KEV" is labelled "CLI · Dashboard" — CLI does **not** output CVSS/EPSS today → relabel "Dashboard" until Phase 1 ships
- [x] "CRA-ready" → "built for CRA Annex I Part II workflows" (or keep "CRA-ready" only with the CRA section's disclaimer) — never "CRA compliant", "powered by ENISA", no ENISA/EU logo
- [x] Add source credit "Vulnerability data: ENISA EUVD (source acknowledged)" to README (+ Data Sources table) · [x] website footer
- [x] Update CLAUDE.md: CLI does not surface EPSS today ("enriched with … EPSS" is only true for the dashboard)

## Phase 1 — EUVD-first enrichment (scanner, CLI, MCP)

- [x] **Wave 0:** fixtures (`kev/dump` excerpt incl. one `eukev_kev`-only entry, `enisaid` sample, 204 case); check whether Grype JSON exposes KEV/EPSS per match
- [x] Move `enrichVulnerabilities()` + `resolveCveId()` into `@ottersight/scanner` (`src/enrich.ts`); CLI + MCP import it; delete `packages/mcp/src/enrich.ts` copy; update CLAUDE.md (Build Order / MCP notes)
- [x] `euvd.ts`: add `loadExploited()` from `GET /api/kev/dump` (24h cache, custom UA) → `Map<cve, {sources, dateAdded, euvdId}>`; fall back to CISA GitHub mirror (`kev.ts`), then empty (D-04)
- [x] Helpers: `parseEuvdDate()` (UTC-anchored), `splitAliases()`, 204/empty-body tolerant fetch
- [x] `EnrichedVuln`: add `exploitedSources`, `exploitedSince`, `cvss`, `epss` (from Grype match); keep `inKev` (deprecated alias)
- [x] Renderers (terminal, markdown, SARIF): EUVD ID first `EUVD-… (CVE-…)`; `EU KEV` vs `CISA KEV`; show EPSS/CVSS; attribution line; SARIF tags `eu-kev` + `kev`, properties `exploitedSources`, `exploitedSince`
- [x] MCP: scan output includes new fields; `check-kev` tool reports sources (EU/CISA); `lookup-euvd` returns EUVD score/EPSS/references via `enisaid`
- [x] README: data sources table with operator + jurisdiction + licence/attribution
- [x] Tests per Validation Architecture in RESEARCH.md; live run on fixture repo (lodash 4.17.20, commons-collections 3.2.1 → must show EU KEV)
- [ ] depwatch dashboard: verify the API worker gets the new fields via `@ottersight/scanner` (separate PR)

## Phase 2 — Sovereign runtime mode

- [ ] Hetzner mirror for Grype DB: daily sync of `databases/v6/latest.json` + `.tar.zst`, sha256 checked against Anchore's listing, same directory layout, monitoring/alert if older than 72h
- [ ] `scanLocal({ sovereign })` / CLI `--eu-sources`: pass env to `execFile` (`GRYPE_DB_UPDATE_URL`, `GRYPE_CHECK_FOR_APP_UPDATE=false`, `SYFT_CHECK_FOR_APP_UPDATE=false`, `GRYPE_EXTERNAL_SOURCES_ENABLE=false`, `GRYPE_DB_REQUIRE_UPDATE_CHECK=true`)
- [ ] In sovereign mode: skip or label US registry lookups (npm/PyPI/crates/Go/Packagist); CISA fallback off (EUVD `kev/dump` already contains CISA entries)
- [ ] Pin Grype/Syft versions in Dockerfile (no `:latest`); decide DB-in-image vs cache volume
- [ ] NOTICE file: GHSA (CC-BY-4.0), NVD, CISA (CC0), FIRST EPSS, ENISA, Anchore Grype DB
- [ ] Claim wording: "vulnerability data served from EU infrastructure, no US endpoints contacted at scan time" — not "EU-sourced data"

## Phase 3 — Provenance & CRA-ready output

- [ ] `--provenance`: per-scan report of every source (name, operator, jurisdiction, endpoint, data timestamp, DB build date, tool versions)
- [ ] CycloneDX 1.6 output with `vulnerabilities[].source = ENISA EUVD`, `references[]` (CVE/GHSA/EUVD aliases), `ratings[]`, `analysis` (VEX)
- [ ] "SRP draft" export (product, version, CVE, EUVD ID, component, awareness timestamp) to help with the CRA Art. 14 24h early warning — no automatic submission (SRP has no API)

## Later / deferred

- CSAF ingestion (BSI lister, NCSC-NL), CSAF VEX export
- Own Grype DB build (grype-db + vunnel) / EUVD vunnel provider — watch vunnel PR #1156
- Shadowserver honeypot signal (`honeypotObservations`, undocumented)
- CIRCL Vulnerability-Lookup / GCVE as EU-hosted fallback

## Decisions (2026-09-23)

1. EUVD `kev/dump` is the **default for everyone**, CISA GitHub mirror only as fallback.
2. Grype DB mirror on **Hetzner Object Storage**; monitoring owner still OPEN.
3. Registry lookups in sovereign mode stay on but are **labelled as US endpoints** in output/provenance.
4. Phase 0 copy fixes: **go** (depwatch PR #3 + blog).

## Review

### Phase 0 (2026-09-23)
- ottersight-cli `ed40b39`: README data-sources table + ENISA credit, "NIS2/CRA compliance" wording removed, CLAUDE.md EPSS note.
- depwatch `c8eb057` (PR #3): blog claim/date/timeline fixes (+ `updatedDate`, correction note), F03 → "Dashboard", CRA-ready subline → Annex I Part II, ENISA credit + non-endorsement in footer. `astro check` 0 errors.
- Deviation: kept the "CRA-ready" label (design-system trust signal) but made the subline precise instead of renaming it.

### Phase 1 (2026-09-23)
- Wave 0: Grype JSON has per-match `epss[]` (0–1, FIRST) and `cvss[]`, **no KEV field** → KEV must come from us. EUVD `kev/dump` confirmed CVE-2015-7501 as EU-KEV-only (not in CISA's 1,721).
- Scanner: `loadExploited()` (EUVD `kev/dump` → CISA mirror → empty), `lookupEuvdRecord()` (204-safe, EPSS ÷100), `parseEuvdDate()` (UTC), `splitEuvdList()`; shared `enrichVulnerabilities()` + `formatExploited`/`formatEpss`/`DATA_ATTRIBUTION` moved into `@ottersight/scanner`; CLI/MCP copies deleted.
- `EnrichedVuln`: `exploitedSources`, `exploitedSince`, `cvss`, `epss`; `inKev` kept (deprecated).
- Outputs: EUVD column first, CVSS/EPSS, "EU KEV" / "CISA KEV" / "EU + CISA KEV", summary counts EU-KEV-only, attribution line; SARIF tags `kev` + `eu-kev`, new properties, run-level `dataAttribution`; MCP `check-kev` reports sources/date, `lookup-euvd` returns the EUVD record.
- Tests: 92/92 (scanner 46, cli 31, mcp 15); `tsc --noEmit` clean in all three packages; EUVD date tests pass under `TZ=Europe/Berlin`.
- Live run on fixture (lodash 4.17.20 + commons-collections 3.2.1): commons-collections CVE-2015-7501 flagged "⚠ EU KEV" — the previous CLI reported nothing for it.
- Found: `pnpm lint` is a no-op (no package has a lint script) — CLAUDE.md corrected; adding real lint scripts is a separate task.
- Open: depwatch API worker still uses `loadKev()` (CISA only) — switch to `loadExploited()` in a depwatch PR.
