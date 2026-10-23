The browser suite uses the real auth binary and PostgreSQL, with Chromium's virtual
WebAuthn authenticator. It does not intercept or mock API responses. Use an isolated
database: tests create accounts and credentials. CI runs it against the embedded
production build, as configured below.

Run `just preview` to build and deploy this checkout over HTTPS on piqueld.
Set `E2E_AUTH_URL` and `E2E_SETTINGS_URL` to the printed auth origin and web
settings URL, then run `just web test-browser`. If signup requires an invitation,
provide an unused `E2E_INVITATION`. Previews allow registration without one.

The OIDC checks sign in through a public, untrusted `browser-e2e` client that
calls back to the web origin's `/callback`, returns to its `/settings` after
logout, and may request `openid`, `profile` and `email`.
`just web browser-client ORIGIN` registers it with the auth database configured
in the environment, e.g. `just web browser-client https://localhost:4443`, as CI
does. Previews do not register it by default. The callback is a test
destination; the suite captures its code before exchanging it.

The suite checks consent, the `iss` on each authorization response, a browser
PKCE exchange, an actual ID-token signature using JWKS and WebCrypto, userinfo
CORS, code replay rejection, and a subsequent `prompt=none` request using
remembered consent. Passkey-only
accounts must not acquire email claims.

`CHROMIUM_EXECUTABLE` can select an existing Chromium installation.
`E2E_ALLOW_SELF_SIGNED_TLS=1` permits local test certificates only.

The virtual authenticator registers credentials with backup eligibility and backup
state enabled, exercising server acceptance of synced passkeys. Apple/Google
password-manager synchronization and live Google/GitHub callbacks also need a
manual check with actual providers/devices; this suite does not claim to verify
those external systems.

`developers.spec.ts` registers a confidential client in the developer console,
checks that its secret never reaches storage or URLs, and signs in with it through
the authorization code flow. It needs no pre-registered client, so it also runs
against a preview.

`admin.spec.ts` checks the admin dashboard against a deployment that has one,
such as a preview: a non-administrator sees no admin data, and an administrator
disables an account, whose settings page then loses its session. Set
`E2E_ADMIN_URL` to the dashboard's origin and `E2E_GRANT_ADMIN` to a command that
grants administrator rights to the username appended to it, e.g.
`just auth admin grant` with the deployment's configuration. Without them, the test
is skipped.
