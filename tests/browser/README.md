The browser suite uses the real auth binary and PostgreSQL, with Chromium's virtual
WebAuthn authenticator. It does not intercept or mock API responses. Use an isolated
database: tests create accounts and credentials.

Build `apps/piquel-web` with `VITE_AUTH_ORIGIN` set to the auth origin. Serve that
static build at the service's configured settings URL, then set `E2E_AUTH_URL`
and `E2E_SETTINGS_URL` and run `pnpm test:browser`. If signup requires an invitation,
provide an unused `E2E_INVITATION`. Both origins must support secure contexts;
loopback HTTP requires the service's explicit development mode.

For the verified local configuration, use `AUTH_PUBLIC_BASE_URL=http://localhost:3000`,
`AUTH_PUBLIC_LISTENER=127.0.0.1:3000`, `AUTH_SETTINGS_URL=http://localhost:4173/settings`,
and `AUTH_DEVELOPMENT_MODE=true`. Set `AUTH_CLIENTS_FILE` to a JSON file containing:

```json
[
  {
    "id": "browser-e2e",
    "display_name": "Browser E2E",
    "redirect_uris": ["http://localhost:4173/callback"],
    "post_logout_uris": ["http://localhost:4173/settings"],
    "allowed_scopes": ["openid", "profile", "email"],
    "allow_refresh": false,
    "trusted": false
  }
]
```

Omitting `client_secret` makes this a public browser client. Start the auth service
with this configuration and an isolated `AUTH_DATABASE_URL`, then build and serve
settings with `VITE_AUTH_ORIGIN=http://localhost:3000`. Run the suite with
`E2E_AUTH_URL=http://localhost:3000` and
`E2E_SETTINGS_URL=http://localhost:4173/settings`. The callback URL is a test
destination: the suite captures its code and returns to settings before exchanging
it, so no callback implementation is required in the settings frontend.

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
