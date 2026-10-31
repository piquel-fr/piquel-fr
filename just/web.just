set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

lint:
    @pnpm lint

# The TypeScript SDK's unit tests, every shared vector included.
test:
    @pnpm test

# The built TypeScript SDK validating a vector token in Node, Deno, Bun and workerd,
# the Cloudflare Workers runtime. Needs `deno` and `bun`, as CI installs them.
smoke:
    @pnpm --filter @piquel/auth build
    @node packages/auth/test/smoke/smoke.js
    @deno run --allow-read=tests/sdk-vectors packages/auth/test/smoke/smoke.js
    @bun packages/auth/test/smoke/smoke.js
    @pnpm --filter @piquel/auth exec node test/smoke/workerd.js

# Requires a running auth service; see tests/browser/README.md. Builds the
# TypeScript SDK first: browser-client.spec.ts serves the built package to its page.
[positional-arguments]
test-browser *ARGS:
    @pnpm --filter @piquel/auth build
    @pnpm test:browser "$@"

# tests/browser/oidc.spec.ts, related-origins.spec.ts, browser-client.spec.ts and
# sdk.spec.ts serve the clients' pages themselves and name the same origins. Register
# the browser checks' public OIDC clients, whose origins have no server, with auth on
# localhost, as in CI, and the confidential client of server.spec.ts's example app,
# with the secret in E2E_SERVER_CLIENT_SECRET.
browser-client:
    @just auth client create browser-e2e --name 'Browser E2E' \
        --redirect-uri https://browser-e2e.test/callback
    @just auth client create browser-e2e-sdk --name 'Browser E2E SDK' --trusted --require-par \
        --redirect-uri https://sdk-e2e.test/callback
    @just auth client create browser-e2e-inline --name 'Browser E2E inline' --trusted \
        --redirect-uri https://localhost:4443/callback
    @just auth client origin add browser-e2e-inline https://localhost:4443
    @just auth client apply browser-e2e-server --name 'Browser E2E server' --trusted --confidential \
        --redirect-uri http://127.0.0.1:4100/auth/callback --post-logout-uri http://127.0.0.1:4100/ \
        --secret env://E2E_SERVER_CLIENT_SECRET

audit:
    @pnpm audit
