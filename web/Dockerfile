# Khandaq web image. Build context is the repository root: `docker build -f web/Dockerfile .`
# Until the React SPA lands (spec 007), this serves the product page as the landing and proxies
# /api to the control-plane API.
FROM caddy:2-alpine
COPY web/Caddyfile /etc/caddy/Caddyfile
COPY site/ /srv/
EXPOSE 80
