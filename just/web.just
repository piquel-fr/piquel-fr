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

audit:
    @pnpm audit
