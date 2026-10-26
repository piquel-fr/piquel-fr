set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

lint:
    @pnpm lint

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
