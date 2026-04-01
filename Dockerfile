# Usage: docker run --rm -v $(pwd):/repo ghcr.io/ottersight/cli scan /repo
#
# Multi-stage build:
# 1. Copy Syft + Grype binaries from official Anchore images (no curl|sh supply chain risk)
# 2. Build CLI + scanner with pnpm in Chainguard node:latest-dev
# 3. Install production deps with npm (no symlinks) for clean runtime copy
# 4. Minimal Chainguard Node runtime (near-zero CVEs, runs as nonroot user)

# Stage 1: Syft binary — official Anchore image, binary at /syft
FROM anchore/syft:latest AS syft

# Stage 2: Grype binary — official Anchore image, binary at /grype
FROM anchore/grype:latest AS grype

# Stage 3: Build stage — cgr.dev/chainguard/node:latest-dev has npm, pnpm, and shell
FROM cgr.dev/chainguard/node:latest-dev AS builder
WORKDIR /app

# Copy all source files with correct ownership (Chainguard runs as node user)
COPY --chown=node:node packages/scanner/package.json packages/scanner/
COPY --chown=node:node packages/scanner/tsup.config.ts packages/scanner/
COPY --chown=node:node packages/scanner/tsconfig.json packages/scanner/
COPY --chown=node:node packages/scanner/src/ packages/scanner/src/
COPY --chown=node:node packages/cli/package.json packages/cli/
COPY --chown=node:node packages/cli/tsup.config.ts packages/cli/
COPY --chown=node:node packages/cli/tsconfig.json packages/cli/
COPY --chown=node:node packages/cli/src/ packages/cli/src/
COPY --chown=node:node package.json pnpm-workspace.yaml pnpm-lock.yaml ./

# Install deps and build with pnpm
RUN pnpm install --frozen-lockfile && \
    pnpm --filter @ottersight/scanner build && \
    pnpm --filter @ottersight/cli build

# Create a clean deploy directory with npm (no pnpm symlinks)
# Remove workspace:* dep — scanner is copied manually below
RUN mkdir -p /app/deploy && \
    cp -r /app/packages/cli/dist /app/deploy/dist && \
    cat /app/packages/cli/package.json | sed '/"@ottersight\/scanner"/d' > /app/deploy/package.json && \
    cd /app/deploy && npm install --omit=dev --ignore-scripts && \
    mkdir -p /app/deploy/node_modules/@ottersight/scanner && \
    cp -r /app/packages/scanner/dist /app/deploy/node_modules/@ottersight/scanner/dist && \
    cp /app/packages/scanner/package.json /app/deploy/node_modules/@ottersight/scanner/package.json

# Stage 4: Minimal runtime — Chainguard distroless Node (no shell, nonroot user)
FROM cgr.dev/chainguard/node:latest
WORKDIR /app

# Copy deployed CLI (dist + real node_modules, no symlinks)
COPY --from=builder /app/deploy/dist ./dist
COPY --from=builder /app/deploy/node_modules ./node_modules

# Copy Syft + Grype binaries from official Anchore images
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype

# Set working directory to /repo so "scan ." works with volume mounts
WORKDIR /repo

# Entrypoint: node runs the CLI script directly (no shell needed)
ENTRYPOINT ["node", "/app/dist/index.js"]
CMD ["scan", "."]
