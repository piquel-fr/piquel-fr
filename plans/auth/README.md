# Accepted authentication release

This plan supersedes the prototype's phased OIDC/SDK/RPC/frontend/operations stack.
The implementation may reuse sound pieces; prototype compatibility is unnecessary.

The agreed design tree:

- Registration: invitation-only by default, runtime switch for public signup,
  CLI-generated single-use expiring links, username-based passkey-only accounts,
  optional email established from a verified linked provider.
- Authentication: discoverable synced passkeys with username fallback; GitHub and
  Google for ordinary sign-in; social-first signup must enroll its first key.
- Settings: piquel.fr frontend, public auth API, auth-host WebAuthn ceremonies;
  passkey confirmation opens a reusable fixed two-minute window for every sensitive
  change; no social renewal; never remove the last passkey.
- Identity linking: matching email prompts, never auto-links; passkey proof required;
  declining cancels; explicit linking supports different/missing emails; one identity
  per provider; unlink first is the only transfer mechanism; local email stays stable.
- OIDC: configured public/confidential web clients, code + S256 PKCE, remembered
  consent with explicit trusted-client bypass, optional rotating refresh tokens.
- Sessions: 30-day absolute cap, five-minute access tokens, logout blocks future
  central SSO/refresh; credential removal revokes other central sessions.
- Packaging: one Rust auth binary with static SvelteKit auth assets and migration/
  invitation commands; separately built piquel.fr settings; PostgreSQL only.
- Deferred: recovery, public client registration, native/device/machine flows,
  immediate application-wide logout, SDK/RPC scaffolding, deployment and infrastructure.

Validation includes actual PostgreSQL transactions, signed WebAuthn assertions,
local signed provider fixtures and real browser flows. Physical Apple/Google device
checks and live provider login are separate evidence, never implied by virtual tests.
