The browser suite uses the real auth binary and PostgreSQL, with Chromium's virtual
WebAuthn authenticator. It does not intercept or mock auth's responses. Use an
isolated database: tests create accounts and credentials. CI runs it against the
embedded production build, as configured below.

`settings.spec.ts` checks auth's own settings pages: renaming, adding and removing
passkeys, a passkey ceremony that fails, the passkey confirmation the SDK runs,
devices, an email link's token and signing out.

`developers.spec.ts` registers a confidential app in the developer console: a
setting refused beside its input, the secret shown once, in an answer no cache
keeps and nowhere in the URL, history or storage, and the app then signing a user
in, redeeming the code with its secret. Its app runs on `https://console-e2e.test`,
which the test serves as `oidc.spec.ts` does its client.

`oidc.spec.ts` signs in through `browser-e2e`, a public, untrusted client at
`https://browser-e2e.test` that may request `openid`, `profile` and `email`. No
server runs it: the test serves its pages through DevTools, so the client's fetches
to auth are genuinely cross-origin, under auth's real CORS policy. It checks
consent, posted once on a double click, the `iss` on each authorization response,
a PKCE exchange, an ID-token signature verified with JWKS and WebCrypto, userinfo,
code replay rejection, a `prompt=none` request using remembered consent, and a
step-up re-authentication. Passkey-only accounts must not acquire email claims.
`just web browser-client` registers the client with the auth database configured in
the environment, as CI does. Previews do not register it by default: run
`auth-service client create browser-e2e --name 'Browser E2E' --redirect-uri
https://browser-e2e.test/callback` there.

Run `just preview` to build and deploy this checkout over HTTPS on piqueld. Set
`E2E_AUTH_URL` to the printed auth origin, then run `just web test-browser`. If
signup requires an invitation, provide an unused `E2E_INVITATION`. Previews allow
registration without one.

`CHROMIUM_EXECUTABLE` can select an existing Chromium installation.
`E2E_ALLOW_SELF_SIGNED_TLS=1` permits local test certificates only.

The virtual authenticator registers credentials with backup eligibility and backup
state enabled, exercising server acceptance of synced passkeys. Apple/Google
password-manager synchronization and live Google/GitHub callbacks also need a
manual check with actual providers/devices; this suite does not claim to verify
those external systems.

`admin.spec.ts` checks the admin dashboard against a deployment that has one,
such as a preview: a non-administrator sees no admin data, an administrator
disables an account, whose settings page then loses its session, and the
administrator signs out of the dashboard. Set
`E2E_ADMIN_URL` to the dashboard's origin and `E2E_GRANT_ADMIN` to a command that
grants administrator rights to the username appended to it, e.g.
`just auth admin grant` with the deployment's configuration. Without them, the test
is skipped.
