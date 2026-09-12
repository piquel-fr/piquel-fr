Static SvelteKit pages for the authentication origin. `pnpm --filter @piquel/auth-web build`
produces `build/`, which the Rust auth-service build embeds into its executable.
Node is needed only to build these assets.

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
Account settings are built separately in `apps/piquel-web`.
