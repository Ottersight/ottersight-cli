# Usage: docker run --rm -v $(pwd):/repo ghcr.io/ottersight/cli scan /repo
#
# Multi-stage build:
# 1. Copy Syft + Grype binaries from official Anchore images (no curl|sh supply chain risk)
# 2. Build CLI + scanner with pnpm in Chainguard node:latest-dev
# 3. Install production deps with npm (no symlinks) for clean runtime copy
# 4. Minimal Chainguard Node runtime (near-zero CVEs, runs as nonroot user)
#
# All base images are pinned by digest (tag kept for readability); Dependabot bumps them.

# Stage 1: Syft binary — official Anchore image, binary at /syft
FROM anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02 AS syft

# Stage 2: Grype binary — official Anchore image, binary at /grype
FROM anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 AS grype

# Stage 3: Build stage — cgr.dev/chainguard/node:latest-dev has npm, pnpm, and shell
FROM cgr.dev/chainguard/node:latest-dev@sha256:d181b32cf4c1d4e23c6cbed1736f0b254933acb0a616fd63aedf883d7c2839e5 AS builder
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
RUN mkdir -p /app/deploy /app/grype-cache && \
    cp -r /app/packages/cli/dist /app/deploy/dist && \
    cat /app/packages/cli/package.json | sed '/"@ottersight\/scanner"/d' > /app/deploy/package.json && \
    cd /app/deploy && npm install --omit=dev --ignore-scripts && \
    mkdir -p /app/deploy/node_modules/@ottersight/scanner && \
    cp -r /app/packages/scanner/dist /app/deploy/node_modules/@ottersight/scanner/dist && \
    cp /app/packages/scanner/package.json /app/deploy/node_modules/@ottersight/scanner/package.json

# Stage 4: Minimal runtime — Chainguard distroless Node (no shell, nonroot user)
FROM cgr.dev/chainguard/node:latest@sha256:5d6d6287abf176121b173a0337a888900f2909f0ac06e4e096138be4898a8f92
WORKDIR /app

# Copy deployed CLI (dist + real node_modules, no symlinks)
COPY --from=builder /app/deploy/dist ./dist
COPY --from=builder /app/deploy/node_modules ./node_modules

# Copy Syft + Grype binaries from official Anchore images
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype

# Licenses and third-party notices (Apache-2.0 requires shipping the license with Syft/Grype)
COPY LICENSE NOTICE /usr/share/doc/ottersight/
COPY LICENSES/ /usr/share/doc/ottersight/LICENSES/

# Grype DB cache: nonroot-owned so a named volume mounted here inherits write access
# (docker run -v ottersight-grype-db:/var/cache/grype ...). Without a volume the DB is
# downloaded on every run.
COPY --from=builder --chown=65532:65532 /app/grype-cache /var/cache/grype
ENV GRYPE_DB_CACHE_DIR=/var/cache/grype

# Set working directory to /repo so "scan ." works with volume mounts
WORKDIR /repo

# Entrypoint: node runs the CLI script directly (no shell needed)
ENTRYPOINT ["node", "/app/dist/index.js"]
CMD ["scan", "."]
