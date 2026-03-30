# Usage: docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
#
# Multi-stage build:
# 1. Copy Syft + Grype binaries from official Anchore images (no curl|sh supply chain risk)
# 2. Build CLI with pnpm ci + tsup in Chainguard node:latest-dev (has shell + npm/pnpm)
# 3. Minimal Chainguard Node runtime (near-zero CVEs, runs as nonroot user)

# Stage 1: Syft binary — official Anchore image, binary at /syft
FROM anchore/syft:latest AS syft

# Stage 2: Grype binary — official Anchore image, binary at /grype
FROM anchore/grype:latest AS grype

# Stage 3: Build stage — cgr.dev/chainguard/node:latest-dev has npm, pnpm, and shell
# We need the dev variant here because the distroless runtime has no package manager
FROM cgr.dev/chainguard/node:latest-dev AS builder
WORKDIR /app

# Copy scanner package sources (CLI depends on @ottersight/scanner)
COPY packages/scanner/package.json packages/scanner/
COPY packages/scanner/tsup.config.ts packages/scanner/
COPY packages/scanner/tsconfig.json packages/scanner/
COPY packages/scanner/src/ packages/scanner/src/

# Copy CLI package sources
COPY packages/cli/package.json packages/cli/
COPY packages/cli/tsup.config.ts packages/cli/
COPY packages/cli/tsconfig.json packages/cli/
COPY packages/cli/src/ packages/cli/src/

# Copy root workspace config for pnpm workspaces
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./

# Install pnpm, install deps, build scanner then CLI
# Scanner must be built first so dist/index.d.ts exists for CLI typecheck
RUN npm install -g pnpm && \
    pnpm install --frozen-lockfile && \
    pnpm --filter @ottersight/scanner build && \
    pnpm --filter @ottersight/cli build

# Stage 4: Minimal runtime — Chainguard distroless Node (no shell, nonroot user)
# cgr.dev/chainguard/node entrypoint is /usr/bin/node — we pass args directly via ENTRYPOINT
FROM cgr.dev/chainguard/node:latest
WORKDIR /app

# Copy built CLI dist and its node_modules from builder
COPY --from=builder /app/packages/cli/dist ./dist
COPY --from=builder /app/packages/cli/node_modules ./node_modules

# Copy scanner dist and package.json into the CLI's node_modules directory
# (workspace symlink won't exist in runtime stage; copy manually)
COPY --from=builder /app/packages/scanner/dist ./node_modules/@ottersight/scanner/dist
COPY --from=builder /app/packages/scanner/package.json ./node_modules/@ottersight/scanner/package.json

# Copy Syft + Grype binaries from official Anchore images
# Using binary copy pattern (not install script) eliminates supply chain risk
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype

# Volume mount point for user's repo — convention: mount local directory at /repo
# docker run --rm -v $(pwd):/repo ottersight/cli scan /repo
VOLUME ["/repo"]

# Entrypoint: node runs the CLI script directly (no shell needed)
# CMD provides default scan target; override by passing different args to docker run
ENTRYPOINT ["node", "/app/dist/index.js"]
CMD ["scan", "/repo"]
