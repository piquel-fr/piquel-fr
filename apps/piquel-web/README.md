The piquel.fr SvelteKit server. Today it serves account settings at `/` and
`/settings`, the account's security history at `/settings/history`, the apps it
has granted access at `/settings/apps`, and `GET /healthz` for piqueld.

It runs on Node with `@sveltejs/adapter-node`: `just web build-settings`
produces `build/`, which `AUTH_ORIGIN=https://auth.piquel.fr node build` serves
on port 3000 (`PORT` changes it). adapter-node bundles `devDependencies` into
`build/` and leaves `dependencies` external, so every dependency belongs in
`devDependencies` and `build/` needs no `node_modules`. The server keeps no state
and has no database: anything it renders comes from auth's HTTP API.

`AUTH_ORIGIN` is read at runtime, so one build serves every environment. The
server refuses to start unless it is a bare `https://` origin. Pages receive it as
root layout data. `src/hooks.server.ts` adds
`frame-ancestors 'none'; connect-src 'self' <AUTH_ORIGIN>` as a second CSP to
every page and endpoint response, with `X-Frame-Options: DENY`, `nosniff`,
`strict-origin-when-cross-origin`, HSTS and, on HTML, `Cache-Control: no-store`.
Framing is forbidden because other `piquel.fr` sites, previews included, share
the auth cookie's site. Ingress adds none of these headers. The hook comes from `@piquel/auth-sdk/server`, for reuse by other piquel.fr servers.
Built assets, and SvelteKit's trailing-slash redirects, are served before the hook
runs, so they do not get these headers.

`just dev` runs Vite against an auth service at `http://localhost:3000`; set
`AUTH_ORIGIN` to use another. In development, loopback `http://` origins are
accepted too. `just web test` builds the server and checks its headers and
startup validation.

Settings call the public auth API with credentialed requests and a CSRF header.
The auth service must allow this exact settings origin and configure its complete
settings URL. All WebAuthn operations redirect to the auth origin. When an action needs a recent
passkey confirmation, the SDK's `StepUp` sends the user to auth's `/confirm` page and
finishes the action on return; the API checks the confirmation in PostgreSQL.
This frontend never stores access or refresh tokens. It uses the shared
`packages/auth-sdk` SDK; `just web fmt`, `just web lint` and `just web check`
format, lint and type-check all web code.

For validation with the real Rust service, see `tests/browser/README.md`.

Use `just preview` from the repository root to try changes over HTTPS on piqueld.
