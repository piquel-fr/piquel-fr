Static SvelteKit account settings, available at `/` and `/settings`.

`VITE_AUTH_ORIGIN=https://auth.piquel.fr just build-settings-web`
produces the standalone `build/` directory. This public build setting also
configures the page's CSP. Without it, the page reads `auth_origin` from
`/config.json` at runtime, as deployed images do (see `infra/README.md`).

Settings call the public auth API with credentialed requests and a CSRF header.
The auth service must allow this exact settings origin and configure its complete
settings URL. All WebAuthn operations redirect to the auth origin; the two-minute
management authorization remains in PostgreSQL and is checked by the API.
This frontend never stores access or refresh tokens. It uses the shared
`packages/auth-sdk` SDK; `just fmt-web`, `just lint-web` and `just check-web`
format, lint and type-check all web code.

For validation with the real Rust service, see `tests/browser/README.md`.

Use `just preview` from the repository root to try changes over HTTPS on piqueld.
