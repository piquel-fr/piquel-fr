Static SvelteKit account settings, available at `/` and `/settings`.

`VITE_AUTH_ORIGIN=https://auth.piquel.fr pnpm --filter @piquel/piquel-web build`
produces the standalone `build/` directory. The default auth origin is
`https://auth.piquel.fr`. This public build setting also configures the page's CSP.

Settings call the public auth API with credentialed requests and a CSRF header.
The auth service must allow this exact settings origin and configure its complete
settings URL. All WebAuthn operations redirect to the auth origin; the two-minute
management authorization remains in PostgreSQL and is checked by the API.
This frontend never stores access or refresh tokens.

For validation with the real Rust service, see `tests/browser/README.md`.
