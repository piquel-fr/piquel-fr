set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

lint:
    @pnpm lint

# The TypeScript SDK's unit tests, every shared vector included, with line, branch
# and function coverage of its sources.
test:
    @pnpm test

# workerd is the Cloudflare Workers runtime. Needs `bun`, as CI installs it.
# Validate a vector token with the built TypeScript SDK in Node, Bun and workerd.
smoke:
    @pnpm --filter @sourceorigin/auth build
    @node packages/auth/test/smoke/smoke.js
    @bun packages/auth/test/smoke/smoke.js
    @pnpm --filter @sourceorigin/auth exec node test/smoke/workerd.js

# Builds the TypeScript SDK first, as browser-client.spec.ts serves the built package.
# Requires a running auth service; see tests/browser/README.md.
[positional-arguments]
test-browser *ARGS:
    @pnpm --filter @sourceorigin/auth build
    @pnpm test:browser "$@"

# The browser checks' clients have origins with no server: tests/browser/oidc.spec.ts,
# browser-client.spec.ts and sdk.spec.ts serve the clients'
# pages themselves and name the same origins. server.spec.ts's example app is a
# confidential client, whose secret is in E2E_SERVER_CLIENT_SECRET.
# Register the browser checks' OIDC clients with auth on localhost, as in CI.
browser-client:
    @just auth client create browser-e2e --name 'Browser E2E' --reason 'Browser tests' \
        --redirect-uri https://browser-e2e.test/callback
    @just auth client create browser-e2e-sdk --name 'Browser E2E SDK' --trusted --require-par \
        --reason 'Browser tests' --redirect-uri https://sdk-e2e.test/callback
    @just auth client create browser-e2e-inline --name 'Browser E2E inline' --trusted \
        --reason 'Browser tests' --redirect-uri https://localhost:4443/callback
    @just auth client origin add browser-e2e-inline https://localhost:4443 --reason 'Browser tests'
    @just auth client apply browser-e2e-server --name 'Browser E2E server' --trusted --confidential \
        --reason 'Browser tests' \
        --redirect-uri http://127.0.0.1:4100/auth/callback --post-logout-uri http://127.0.0.1:4100/ \
        --secret env://E2E_SERVER_CLIENT_SECRET

# Unused files, exports and dependencies, by knip; knip.json lists its entry points.
unused:
    @pnpm unused

audit:
    @pnpm audit
