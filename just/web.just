set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

lint:
    @pnpm lint

# The TypeScript SDK's unit tests, every shared vector but the callbacks included.
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

# Requires a running auth service; see tests/browser/README.md.
[positional-arguments]
test-browser *ARGS:
    @pnpm test:browser "$@"

# tests/browser/oidc.spec.ts and related-origins.spec.ts serve the clients' pages
# themselves and name the same origins. Register the browser checks' public OIDC
# clients, whose origins have no server, with auth on localhost, as in CI.
browser-client:
    @just auth client create browser-e2e --name 'Browser E2E' \
        --redirect-uri https://browser-e2e.test/callback
    @just auth client create browser-e2e-inline --name 'Browser E2E inline' --trusted \
        --redirect-uri https://localhost:4443/callback
    @just auth client origin add browser-e2e-inline https://localhost:4443

audit:
    @pnpm audit
