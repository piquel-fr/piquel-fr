FROM node:24-bookworm-slim AS frontend
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
COPY apps/piquel-web apps/piquel-web
COPY packages/auth-sdk packages/auth-sdk
RUN pnpm install --frozen-lockfile --filter @piquel/piquel-web...
# No AUTH_ORIGIN: one image serves every environment. The server reads it at
# startup and refuses to start without a valid one (see src/hooks.server.ts).
RUN pnpm --filter @piquel/piquel-web build

# adapter-node bundles devDependencies, piquel-web's only dependencies, into build/,
# so the image needs no node_modules.
FROM node:24-bookworm-slim
WORKDIR /app
COPY --from=frontend --chmod=644 /app/apps/piquel-web/package.json ./
COPY --from=frontend /app/apps/piquel-web/build build
USER node
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node", "build"]
