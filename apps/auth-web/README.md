Static SvelteKit pages for the authentication origin. `just web build`
produces `build/`, and builds the SDK script, which the Rust auth-service build
embeds into its executable.
Node is needed only to build these assets.

Run `just preview` from the repository root to develop over HTTPS on piqueld.
It builds these pages with the Rust service and prints the preview's URLs.
Run it again after changing code. See the root README for configuration.

Passkey ceremonies, login and social linking run here. Consent, logout and the
account settings are server-rendered by auth-service.
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
API, passkey and redirect helpers come from the shared `packages/auth-sdk` SDK.
`just web fmt`, `just web lint` and `just web check` format, lint and type-check
all web code.
