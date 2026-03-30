# Contributing to OtterSight CLI

Thank you for your interest in contributing! OtterSight CLI is the open-core scanner at the heart of [OtterSight](https://ottersight.com). Community contributions make it better for everyone.

## Scope

**In scope for this repo:**

- Scanner core (`@ottersight/scanner`): SBOM generation, CVE detection, KEV enrichment, EUVD mapping, version lookups, output formatting
- CLI features (`@ottersight/cli`): new flags, output formats (SARIF, HTML, JSON), UX improvements
- New registry support (npm, PyPI, crates.io, Go, Maven, etc.)
- New ecosystem support for Syft/Grype output parsing
- Bug fixes and documentation

**Out of scope for this repo:**

Anything that overlaps with OtterSight Cloud is managed in a separate private repo:
- Dashboard UI and web frontend
- Scheduled/automated scans
- Notifications (email, Slack, webhooks)
- Multi-repo management and fleet scanning
- User accounts, billing, and team management

If you're unsure whether your idea belongs here, open a [GitHub Discussion](https://github.com/Ottersight/ottersight-cli/discussions) first.

## Prerequisites

Before you start, make sure you have:

- **Node.js 20+** — [nodejs.org](https://nodejs.org)
- **pnpm** — `npm install -g pnpm`
- **[Syft](https://github.com/anchore/syft)** on PATH — SBOM generation
- **[Grype](https://github.com/anchore/grype)** on PATH — CVE scanning

To install Syft and Grype on macOS:

```bash
brew install anchore/grype/grype anchore/syft/syft
```

On Linux:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

## Setup

```bash
git clone https://github.com/Ottersight/ottersight-cli.git
cd ottersight-cli
pnpm install
pnpm build
pnpm test
```

All tests should pass before you start making changes.

## Development Workflow

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Make your changes
3. Run `pnpm typecheck` and `pnpm test` to verify nothing is broken
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) (see below)
5. Push to your fork and open a Pull Request against `main`
6. CI must pass before a PR can be merged

## Coding Style

- **TypeScript strict mode** — no `any` unless justified with an inline comment explaining why
- **Vitest for tests** — code changes should include tests. Docs and typo fixes don't need tests
- **No new runtime dependencies without discussion first** — open a Discussion or issue before adding packages. We keep the dependency footprint minimal

## Conventional Commits

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | When to use |
|--------|-------------|
| `feat:` | New feature or capability |
| `fix:` | Bug fix |
| `docs:` | Documentation changes only |
| `test:` | Adding or updating tests |
| `refactor:` | Code restructuring with no behavior change |
| `chore:` | Tooling, config, dependencies, CI |

Examples:
- `feat: add SARIF output format`
- `fix: handle empty SBOM from Syft`
- `docs: update CONTRIBUTING.md setup steps`

## PR Review

This project uses a **BDFL model** — [@olivermark](https://github.com/olivermark) reviews and merges all PRs.

- Expect feedback within a few days (usually faster)
- Keep PRs focused on a single concern — small, focused PRs get reviewed faster
- If your PR is large, consider splitting it into smaller pieces
- Discuss large changes in a GitHub Discussion or issue before starting implementation

## License

By contributing, you agree that your contributions are licensed under the [MIT License](./LICENSE).
