# syntax=docker/dockerfile:1

# ---- Stage 1: build -------------------------------------------------------
# Compiler and dev dependencies live only in this stage. Nothing from here
# reaches the final image unless it is explicitly copied.
FROM node:24.22.3-alpine3.24 AS build
WORKDIR /app

# Copy manifests first: this layer is cached until dependencies change,
# so editing source code does not re-download packages.
COPY package.json package-lock.json ./
# "npm ci" installs exactly what the lockfile says and fails if it is out of
# sync - reproducible builds, no silent version drift.
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
# Compile, then drop devDependencies so only runtime packages are copied on.
RUN npm run build && npm prune --omit=dev

# ---- Stage 2: runtime -----------------------------------------------------
# Trade-off: alpine (not distroless) on purpose. A distroless image has no
# shell, which is better in production, but this lab needs a shell in the
# VULNERABLE overlay to demonstrate what an attacker can do in a container.
FROM node:24.22.3-alpine3.24 AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# Numeric UID:GID instead of a user name: Kubernetes "runAsNonRoot: true" can
# only verify a numeric UID. Files above stay root-owned, so the app user
# cannot modify its own code even without a read-only root filesystem.
USER 1000:1000

EXPOSE 3000
# Exec form: node is PID 1 and receives SIGTERM directly (graceful shutdown).
CMD ["node", "dist/server.js"]
