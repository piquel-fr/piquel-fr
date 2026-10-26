set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

lint:
    @pnpm lint

# The SDK script auth's pages load, which the Rust build embeds.
build:
    @pnpm build

# Requires a running auth service; see tests/browser/README.md.
[positional-arguments]
test-browser *ARGS:
    @pnpm test:browser "$@"

# tests/browser/oidc.spec.ts serves the client's pages itself and names the same origin.
# Register the browser checks' public OIDC client, whose origin has no server.
browser-client:
    @just auth client create browser-e2e --name 'Browser E2E' \
        --redirect-uri https://browser-e2e.test/callback

audit:
    @pnpm audit
