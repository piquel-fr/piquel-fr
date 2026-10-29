The browser suite uses the real auth binary and PostgreSQL, with Chromium's virtual
WebAuthn authenticator. It does not intercept or mock auth's responses. Use an
isolated database: tests create accounts and credentials. CI runs it against the
debug binary `just rust build` makes, behind Caddy over HTTPS, as configured below.

`settings.spec.ts` checks auth's own settings pages: renaming, adding and removing
passkeys, a passkey ceremony that fails, the passkey confirmation the passkey
script runs, devices, an email link's token and signing out.

`sign-in.spec.ts` signs in with a handle, after a handle this authenticator holds
no passkey for is refused in the form. Every spec signs up through `/register`.

`deletion.spec.ts` downloads the account's data from `/settings/data`, deletes the
account by typing its handle, and restores it: signing in with its passkey offers to
restore it instead of a session, and restoring signs in.

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
`related-origins.spec.ts` signs in on a client application's own page with a
passkey, through `browser-e2e-inline`, a trusted client approved as a related
origin. Its page, served like `browser-e2e`'s, gets the code as JSON, with no auth
cookie, and redeems it with its PKCE verifier; replaying the ceremony fails. With
auth on `localhost`, as in CI, the page is at `https://localhost:4443`, on auth's
own host, where browsers need no list. Elsewhere it is at
`https://related-e2e.test`, another site, so the browser reads auth's
`/.well-known/webauthn` first.

`just web browser-client` registers both clients with the auth database configured
in the environment, as CI does. Previews do not register them by default: run
`auth-service client create browser-e2e --name 'Browser E2E' --redirect-uri
https://browser-e2e.test/callback`, `auth-service client create browser-e2e-inline
--name 'Browser E2E inline' --trusted --redirect-uri
https://related-e2e.test/callback` and `auth-service client origin add
browser-e2e-inline https://related-e2e.test` there.

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

`admin.spec.ts` checks the admin dashboard, which CI serves on its own host,
`admin.localhost`: a non-administrator is handed nothing, an administrator signs in
through auth's handoff page, confirms a change with a passkey for the dashboard
only, and disables an account, whose settings page then loses its session; signing
out of the dashboard keeps the Piquel session, and signed out of both, a passkey
sign-in on auth goes on to the dashboard. Set `E2E_ADMIN_URL` to the
dashboard's origin and `E2E_GRANT_ADMIN` to a command that grants administrator
rights to the handle appended to it, e.g. `just auth admin grant` with the
deployment's configuration. Without them, the test is skipped.

`recovery.spec.ts` recovers an account as support does, against a deployment
whose CLI it can run, such as a preview. `user recover` prints the link, which a
second browser opens to add a passkey: it lands on settings with the probation's
restriction and the question "Was this you?", which stays answered there across
page loads. The owner's browser, which the start signed out, signs in with the
passkey from before the recovery, follows the question to the undo page and
undoes the recovery, which signs the second browser out. Set `E2E_RECOVER` to a
command that runs `auth-service user recover` on the deployment, to which the
test appends the handle, a reason and `--yes`, e.g. `just auth user recover`
with the deployment's configuration, or `piquelctl preview exec piquel-fr
<branch> auth -- auth-service user recover` for a preview. Without it, the test
is skipped.
