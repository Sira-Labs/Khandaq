# Khandaq web image: build the SPA, serve it with Caddy, proxy /api to the control plane.
# Build context is the repository root: `docker build -f web/Dockerfile .`
FROM node:22-slim AS build
WORKDIR /app
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM caddy:2-alpine
COPY web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 80
