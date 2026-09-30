FROM node:24-bookworm-slim AS frontend
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
COPY apps/piquel-web apps/piquel-web
COPY packages/browser packages/browser
RUN pnpm install --frozen-lockfile --filter @piquel/piquel-web...
# Piqueld cannot pass build arguments, so build once per environment's auth origin.
# nginx.conf selects the build from the request's hostname.
RUN VITE_AUTH_ORIGIN=https://auth.piquel.fr pnpm --filter @piquel/piquel-web build \
    && mkdir /sites && mv apps/piquel-web/build /sites/prod
RUN VITE_AUTH_ORIGIN=https://auth.dev.piquel.fr pnpm --filter @piquel/piquel-web build \
    && mv apps/piquel-web/build /sites/dev

FROM nginx:stable-bookworm
RUN apt-get update \
    && apt-get install --yes --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/* /usr/share/nginx/html/*
COPY infra/nginx.conf /etc/nginx/nginx.conf
COPY --from=frontend /sites /usr/share/nginx/html
USER nginx
EXPOSE 8080
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
