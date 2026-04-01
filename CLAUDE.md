# OtterSight CLI

Open-source Software Composition Analysis (SCA) scanner. Scans projects for vulnerable dependencies using Syft + Grype, enriched with EUVD, CISA KEV, and EPSS data.

## Architecture

```
@ottersight/scanner     — Core scanning library (scanLocal, KEV, EUVD, registries)
    ↓
@ottersight/cli         — Terminal UI (Commander.js, chalk, cli-table3)
@ottersight/mcp         — MCP server for AI assistants (Claude Code, Cursor)
```

Scanner is the shared library. CLI and MCP are consumers with different output targets.

## Package Structure

```
packages/
├── scanner/src/
│   ├── scan.ts          — Runs Syft + Grype via execFile(), returns ScanResult
│   ├── kev.ts           — CISA KEV lookup (GitHub mirror, 24h cache)
│   ├── euvd.ts          — ENISA EUVD mapping (CSV dump, 24h cache)
│   ├── registries.ts    — npm/PyPI/crates.io/Go/Packagist version lookups
│   ├── logger.ts        — Zero-dep structured JSON logging (ECS format)
│   ├── types.ts         — All shared type contracts
│   └── index.ts         — Barrel export
├── cli/src/
│   ├── index.ts         — Commander.js entry point (#!/usr/bin/env node via tsup banner)
│   ├── commands/scan.ts — Scan orchestration (deps check → scan → enrich → render)
│   ├── enrich.ts        — GrypeMatch → EnrichedVuln (joins KEV/EUVD, dedup)
│   ├── check-deps.ts    — Verifies syft/grype on PATH, prints install instructions
│   └── render/
│       ├── terminal.ts  — Colored severity table (chalk + cli-table3)
│       └── markdown.ts  — GitHub-style MD with shields.io badge + collapsible details
└── mcp/src/
    ├── index.ts         — MCP server entry, registerTool() with zod schema
    └── enrich.ts        — Copied from CLI (avoids circular workspace dep)
```

## Commands

```bash
pnpm install              # Install all dependencies
pnpm build                # Build scanner first, then CLI (order matters)
pnpm test                 # Run all tests (vitest)
pnpm lint                 # Typecheck all packages

# Package-specific
pnpm --filter @ottersight/scanner build
pnpm --filter @ottersight/cli build
pnpm --filter @ottersight/mcp build

# Run locally
node packages/cli/dist/index.js scan .
npx @ottersight/cli scan .

# Docker
docker build -f Dockerfile -t ottersight/cli .
docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
```

## Build Order

Scanner MUST be built before CLI. CLI imports `@ottersight/scanner` and needs `dist/index.d.ts` for TypeScript resolution. The MCP package copies `enrich.ts` inline to avoid this dependency.

## Key Conventions

- **Graceful degradation:** KEV, EUVD, and registry lookups never throw. Network failures return empty data. The scan still completes.
- **Module-level caches:** `kev.ts` and `euvd.ts` use module-level `Set`/`Map` with 24h TTL. This means `vi.resetModules()` is required per test.
- **Dedup by tuple:** Vulnerabilities are deduplicated by `(packageName, packageVersion, cveId)` in `enrich.ts`. Same advisory across multiple manifests counts once.
- **CVE resolution:** Grype sometimes returns GHSA IDs instead of CVEs. `resolveCveId()` checks `relatedVulnerabilities` for a CVE- prefix to enable EUVD/KEV enrichment.
- **Markdown emoji:** Uses unicode escape sequences (`\uD83D\uDD34`) not chalk. Guarantees zero ANSI contamination in Markdown output.
- **Shebang via tsup:** CLI entry point gets `#!/usr/bin/env node` via tsup `banner` config, not manually.

## Testing Patterns

Vitest with specific patterns for this codebase:

### vi.hoisted() for module-level mocks
```typescript
const mockExecFile = vi.hoisted(() => vi.fn())
vi.mock("node:child_process", () => ({ execFile: mockExecFile }))
```
Vitest hoists `vi.mock()` before const declarations. `vi.hoisted()` runs first.

### promisify.custom symbol (scan.test.ts)
```typescript
mockExecFile[Symbol.for('nodejs.util.promisify.custom')] = vi.fn(...)
```
Node.js `promisify()` checks this symbol. Attach mock function here.

### vi.resetModules() for cached modules (kev/euvd tests)
```typescript
beforeEach(() => vi.resetModules())
```
Module-level caches (`kevSet`, `euvdMap`) persist between tests without this.

### vi.stubGlobal() for fetch
```typescript
vi.stubGlobal('fetch', mockFetch)
// cleanup: vi.unstubAllGlobals()
```

## Release Workflow

1. Bump version in `package.json` (scanner, cli, mcp)
2. `pnpm build && pnpm test`
3. Git tag: `git tag vX.Y.Z`
4. Push tag: `git push origin vX.Y.Z`
5. GitHub Actions (`.github/workflows/publish.yml`):
   - Typecheck → build → test → npm publish → GitHub Release
   - Release notes auto-generated from PR labels (`.github/release.yml`)
   - Categories: Breaking Changes, New Features, Bug Fixes, Documentation, Other

## Docker Build

Multi-stage Chainguard build (Dockerfile):
1. **Stage 1-2:** Copy Syft + Grype binaries from official Anchore images
2. **Stage 3:** Build with `cgr.dev/chainguard/node:latest-dev` (has pnpm, shell)
   - Build scanner → build CLI
3. **Stage 4:** Runtime with `cgr.dev/chainguard/node:latest` (distroless, nonroot)
   - Scanner dist copied manually into `node_modules/@ottersight/scanner` (workspace symlinks don't exist in distroless)

## Enrichment Pipeline

```
Grype matches
    → resolveCveId() (GHSA → CVE lookup via relatedVulnerabilities)
    → join with KEV Set (isKnownExploited)
    → join with EUVD Map (euvdId)
    → dedup by (package, version, cveId)
    → EnrichedVuln[]
```

## Supported Ecosystems

Via Syft: npm, pip, cargo, go, maven, gradle, nuget, rubygems, composer, cocoapods, conan, hex, pub, swift, and more (20+).

Version lookups implemented for: npm, PyPI, crates.io, Go proxy, Packagist.

## External Data Sources

| Source | URL | Cache | Fallback |
|--------|-----|-------|----------|
| CISA KEV | GitHub mirror (cisagov/kev-data) | 24h in-memory | Empty Set |
| EUVD | ENISA CSV dump API | 24h in-memory | Empty Map |
| npm | registry.npmjs.org | None | null version |
| PyPI | pypi.org/pypi/{name}/json | None | null version |
| crates.io | crates.io/api/v1/crates/{name} | None | null version |
| Go | proxy.golang.org/{mod}/@latest | None | null version |
| Packagist | repo.packagist.org/p2/{name}.json | None | null version |

## MCP Server

`@ottersight/mcp` exposes one tool: `ottersight-scan`
- `disable-model-invocation: true` — user-triggered only, never auto-invoked by the model
- No arguments — always scans current working directory
- Returns structured content (all vulns in JSON) + truncated Markdown summary
- `enrich.ts` copied inline from CLI to avoid circular workspace dependency

## Contributing

See CONTRIBUTING.md. BDFL model — @olivermark reviews and merges all PRs.
