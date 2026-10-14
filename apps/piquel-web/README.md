The piquel.fr SvelteKit server. Today it serves account settings at `/` and
`/settings`, and `GET /healthz` for piqueld.

It runs on Node with `@sveltejs/adapter-node`: `just build-settings-web`
produces `build/`, which `AUTH_ORIGIN=https://auth.piquel.fr node build` serves
on port 3000 (`PORT` changes it). adapter-node bundles `devDependencies` into
`build/` and leaves `dependencies` external, so every dependency belongs in
`devDependencies` and `build/` needs no `node_modules`. The server keeps no state
and has no database: anything it renders comes from auth's HTTP API.

`AUTH_ORIGIN` is read at runtime, so one build serves every environment. The
server refuses to start unless it is a bare `https://` origin. Pages receive it as
root layout data. `src/hooks.server.ts` adds `connect-src 'self' <AUTH_ORIGIN>`
as a second CSP to every page and endpoint response, with `nosniff`,
`strict-origin-when-cross-origin` and, on HTML, `Cache-Control: no-store`. The
hook comes from `@piquel/auth-sdk/server`, for reuse by other piquel.fr servers.
Built assets, and SvelteKit's trailing-slash redirects, are served before the hook
runs, so they do not get these headers.

`just dev` runs Vite against an auth service at `http://localhost:3000`; set
`AUTH_ORIGIN` to use another. In development, loopback `http://` origins are
accepted too. `just test-web` builds the server and checks its headers and
startup validation.

Settings call the public auth API with credentialed requests and a CSRF header.
The auth service must allow this exact settings origin and configure its complete
settings URL. All WebAuthn operations redirect to the auth origin; the two-minute
management authorization remains in PostgreSQL and is checked by the API.
This frontend never stores access or refresh tokens. It uses the shared
`packages/auth-sdk` SDK; `just fmt-web`, `just lint-web` and `just check-web`
format, lint and type-check all web code.

For validation with the real Rust service, see `tests/browser/README.md`.

Use `just preview` from the repository root to try changes over HTTPS on piqueld.
