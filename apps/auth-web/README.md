Static SvelteKit pages for the authentication origin. `just build-auth-web`
produces `build/`, which the Rust auth-service build embeds into its executable.
Node is needed only to build these assets.

For local development, run `just dev` from the repository root with
`AUTH_DATABASE_URL` set to a local PostgreSQL database (see the root README).
Open `http://localhost:3000`: Vite hot reloads the UI and proxies auth endpoints to
the normal Rust service on port 8080, restarted by cargo-watch. `/login` is a UI
route; `/login/*` contains backend social-login endpoints. The proxy preserves
Origin, cookies and redirects. Running this app's `dev` script alone requires
that backend to already be running with `AUTH_PUBLIC_BASE_URL=http://localhost:3000`.

Passkey ceremonies, login, social linking and authorization confirmation run here.
All configuration comes from the public `/config` endpoint; no provider secrets or
session tokens are placed in the frontend bundle. The auth session uses an HttpOnly
cookie. A signup invitation can be retained in tab sessionStorage across the social
redirect and is removed after successful registration.

On Android, registration and enrollment offer an explicit Google Password Manager
option. Ordinary passkey/security-key registration remains the default. The browser
cannot determine whether Google Password Manager is installed, so this choice is
never made automatically.

SvelteKit emits per-page CSP hashes in HTML. The Rust service adds frame-ancestor
protection in its response header without imposing a conflicting script policy.
Account settings are built separately in `apps/piquel-web`. API, passkey and redirect
helpers come from the shared `packages/auth-sdk` SDK. `just fmt-web`,
`just lint-web` and `just check-web` format, lint and type-check all web code.
