The browser suite uses the real auth binary and PostgreSQL, with Chromium's virtual
WebAuthn authenticator. It does not intercept or mock API responses. Use an isolated
database: tests create accounts and credentials. CI runs it against the embedded
production build, as configured below.

Run `just preview` to build and deploy this checkout over HTTPS on piqueld.
Set `E2E_AUTH_URL` and `E2E_SETTINGS_URL` to the printed auth origin and web
settings URL, then run `just test-browser`. If signup requires an invitation,
provide an unused `E2E_INVITATION`. Previews allow registration without one.

The OIDC checks require a public `browser-e2e` client in `AUTH_CLIENTS_FILE`,
with the preview web origin's `/callback` in `redirect_uris`, `/settings` in
`post_logout_uris`, `openid`, `profile`, and `email` in `allowed_scopes`, and
`trusted: false`. Previews do not configure this client by default. The callback
is a test destination; the suite captures its code before exchanging it.

The suite checks consent, a browser PKCE exchange, an actual
ID-token signature using JWKS and WebCrypto, userinfo CORS, code replay rejection,
and a subsequent `prompt=none` request using remembered consent. Passkey-only
accounts must not acquire email claims.

`CHROMIUM_EXECUTABLE` can select an existing Chromium installation.
`E2E_ALLOW_SELF_SIGNED_TLS=1` permits local test certificates only.

The virtual authenticator registers credentials with backup eligibility and backup
state enabled, exercising server acceptance of synced passkeys. Apple/Google
password-manager synchronization and live Google/GitHub callbacks also need a
manual check with actual providers/devices; this suite does not claim to verify
those external systems.
