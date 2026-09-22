# OtterSight CLI

Open-source Software Composition Analysis (SCA) scanner. Scans projects for vulnerable dependencies using Syft + Grype, enriched with EUVD, CISA KEV, and EPSS data.

> `AGENTS.md` is a symlink to this file. Edit `CLAUDE.md` only.

## Session Start

Read the latest handoff in docs/summaries/ if one exists. Load only the files that handoff references — not all summaries. Review `tasks/lessons.md` for relevant lessons. If no handoff exists, ask: what type of work, what is the target deliverable.

Before starting work, state: what you understand the project state to be, what you plan to do this session, and any open questions.

## Identity

You work with Oliver (@olivermark), founder and BDFL of OtterSight, building an open-source SCA scanner (CLI, scanner library, MCP server). Keep responses short, offer A/B/C options for decisions, don't over-explain.

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately — don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution
- Sub-agent returns must be structured, not free-form prose. Use output contracts from templates/claude-templates.md

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness (`pnpm build && pnpm test && pnpm lint`)

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to `tasks/todo.md`
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

## Context Rules

1. Do not mix unrelated project contexts in one session.
2. Write state to disk, not conversation. After completing meaningful work, write a summary to docs/summaries/ using templates from templates/claude-templates.md. Include: decisions with rationale, exact numbers, file paths, open items.
3. Before compaction or session end, write to disk: every number, every decision with rationale, every open question, every file path, exact next action.
4. When switching work types (research → implementation → review), write a handoff to docs/summaries/handoff-[date]-[topic].md and suggest a new session.
5. Do not silently resolve open questions. Mark them OPEN or ASSUMED.
6. Do not bulk-read documents. Process one at a time: read, summarize to disk, release from context before reading next. For the detailed protocol, read docs/context/processing-protocol.md.

## Where Things Live

- templates/claude-templates.md — summary, handoff, decision, analysis, task, output contract templates (read on demand)
- tasks/todo.md — current task plan with checkable items
- tasks/lessons.md — lessons learned from corrections
- docs/summaries/ — active session state (latest handoff + project brief + decision records + source summaries)
- docs/context/ — reusable knowledge, loaded only when relevant to the current task
  - processing-protocol.md — full document processing steps
  - archive-rules.md — summary lifecycle and file archival rules
  - subagent-rules.md — when to use subagents vs. main agent
  - project-structure.md — context-os directory conventions
- docs/archive/ — processed raw files and superseded handoffs. Do not read unless explicitly told.
- .claude/commands/ — `/handoff`, `/status`, `/process-doc`

This is a public repo: never write secrets, customer data, or confidential strategy into docs/summaries/ or tasks/ (use gitignored `docs/internal/` instead).

## Error Recovery

If context degrades or auto-compact fires unexpectedly: write current state to docs/summaries/recovery-[date].md, tell the user what may have been lost, suggest a fresh session.

## Before Delivering Output

Verify: exact numbers preserved, open questions marked OPEN, output matches what was requested (not assumed), claims backed by specific data, output consistent with stored decisions in docs/summaries/, summary written to disk for this session's work.

---

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
