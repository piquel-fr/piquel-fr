set working-directory := '..'

# Serve piquel-web with Vite against a local auth service; AUTH_ORIGIN overrides it.
dev:
    @AUTH_ORIGIN="${AUTH_ORIGIN:-http://localhost:3000}" pnpm --filter @piquel/piquel-web dev

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
    @pnpm --filter @piquel/auth-web --filter @piquel/piquel-web -r exec svelte-kit sync

build: build-auth build-settings

build-auth:
    @pnpm --filter @piquel/auth-web build

build-settings:
    @pnpm --filter @piquel/piquel-web build

# Starts the production piquel-web server and checks its headers and startup validation.
test: build-settings
    @pnpm --filter @piquel/piquel-web test

# Requires running auth/settings servers; see tests/browser/README.md.
[positional-arguments]
test-browser *ARGS:
    @pnpm test:browser "$@"

# Register the browser checks' public OIDC clients for the settings origin ORIGIN, e.g. https://localhost:4443:
# an untrusted one, and a trusted one whose pages on ORIGIN sign in with passkeys.
browser-client ORIGIN:
    @just auth client create browser-e2e --name 'Browser E2E' \
        --redirect-uri {{ quote(ORIGIN + "/callback") }} \
        --post-logout-uri {{ quote(ORIGIN + "/settings") }}
    @just auth client create browser-e2e-inline --name 'Browser E2E inline' --trusted \
        --redirect-uri {{ quote(ORIGIN + "/callback") }}
    @just auth client origin add browser-e2e-inline {{ quote(ORIGIN) }}

audit:
    @pnpm audit
