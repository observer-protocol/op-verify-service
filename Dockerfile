# Self-hosted Observer Protocol verifier.
#
# Verification only. Nothing from observer-protocol-api or op-mcp-payment-server is present, so
# there is no issuance capability to disable — it was never compiled in.

# ─── build ────────────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsup.config.ts ./
COPY src ./src

# PROVENANCE, PASSED IN RATHER THAN GUESSED.
#
# tsup stamps the build with `git rev-parse HEAD`, and there is no git in this image, so every
# container would otherwise report commit "unknown" at GET /version. "unknown" is the honest answer
# and the config is right to prefer it over an empty string — but it is a worse answer than the one
# the host already has. Pass it and the image carries its real identity; omit it and /version says
# unknown, which is true rather than misleading.
#
#   docker build --build-arg OP_BUILD_COMMIT="$(git rev-parse HEAD)" \
#                --build-arg OP_BUILD_BRANCH="$(git rev-parse --abbrev-ref HEAD)" .
#
# compose.yaml does this for you.
ARG OP_BUILD_COMMIT
ARG OP_BUILD_BRANCH
ARG OP_BUILD_DIRTY
ENV OP_BUILD_COMMIT=${OP_BUILD_COMMIT} \
    OP_BUILD_BRANCH=${OP_BUILD_BRANCH} \
    OP_BUILD_DIRTY=${OP_BUILD_DIRTY}
RUN npm run build

# ─── runtime ──────────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine
WORKDIR /app

# node_modules IS REQUIRED AT RUNTIME, AND NOT ONLY FOR IMPORTS.
#
# assertEngineFloor() reads node_modules/@observer-protocol/policy-engine/package.json to establish
# which engine is actually running, and REFUSES TO START when it cannot: "an unknown version is a
# failure state rather than a pass". A slimmer image that drops node_modules because the bundle
# inlines its imports would not start at all — and the failure would look like a config error rather
# than what it is.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY scripts/gen-did-key.mjs ./scripts/gen-did-key.mjs
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# The signing key and the public-material cache live here. Mount a volume to keep the signing
# identity stable across `compose down` — otherwise every recreate signs as a different did:key.
RUN mkdir -p /var/lib/op-verify && chown -R node:node /var/lib/op-verify /app
VOLUME /var/lib/op-verify

USER node
ENV NODE_ENV=production \
    PORT=8091 \
    OP_VERIFY_SIGNING_KEY_PATH=/var/lib/op-verify/signer.pem \
    OP_VERIFY_CACHE_DIR=/var/lib/op-verify/cache
EXPOSE 8091

# No bearer token is set, deliberately. POST /v1/verify is open: it takes an artifact as input and
# retrieves nothing, so a caller can only check a credential it already holds. Setting
# OP_VERIFY_BEARER_TOKENS here would reintroduce the dead end this container exists to remove.

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8091)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/server.js"]
