FROM node:24-bookworm-slim AS frontend
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
COPY apps/piquel-web apps/piquel-web
COPY packages/browser packages/browser
RUN pnpm install --frozen-lockfile --filter @piquel/piquel-web...
# No VITE_AUTH_ORIGIN: one image serves every environment. The page reads its
# auth origin from /config.json, which nginx serves from AUTH_ORIGIN.
RUN pnpm --filter @piquel/piquel-web build

FROM nginx:stable-bookworm
RUN rm -rf /usr/share/nginx/html/*
COPY infra/nginx.conf /etc/nginx/nginx.conf
COPY --chmod=755 infra/web-entrypoint.sh /usr/local/bin/web-entrypoint
COPY --from=frontend /app/apps/piquel-web/build /usr/share/nginx/html
USER nginx
EXPOSE 8080
ENTRYPOINT ["web-entrypoint"]
