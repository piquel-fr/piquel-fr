set working-directory := '..'

check:
    @pnpm check

fmt:
    @pnpm format

fmt-check:
    @pnpm format:check

# Type-aware linting reads SvelteKit's generated tsconfig files.
lint: generate
    @pnpm lint

# Refresh SvelteKit's generated types/config. Cargo generates its own asset table.
generate:
    @pnpm --filter @piquel/auth-web -r exec svelte-kit sync

# The pages auth embeds: auth-web, and the SDK script its server-rendered pages use.
build:
    @pnpm --filter "@piquel/auth-web..." build

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
