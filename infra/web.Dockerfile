FROM node:24-bookworm-slim AS frontend
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
COPY apps/piquel-web apps/piquel-web
COPY packages/browser packages/browser
RUN pnpm install --frozen-lockfile --filter @piquel/piquel-web...
RUN VITE_AUTH_ORIGIN=http://localhost:8080 pnpm --filter @piquel/piquel-web build

FROM nginx:stable-bookworm
RUN apt-get update \
    && apt-get install --yes --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/* /usr/share/nginx/html/*
COPY infra/nginx.conf /etc/nginx/nginx.conf
COPY --from=frontend /app/apps/piquel-web/build /usr/share/nginx/html
USER nginx
EXPOSE 8080
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
