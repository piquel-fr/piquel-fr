# Browser tests

The browser suite drives Chromium against a running deployment of auth: the real
binary and PostgreSQL, over HTTPS, with Chromium's virtual passkey authenticator.
Nothing is mocked. Each spec says at its top what it covers.

Run it against a deployment you can throw away: the tests create accounts,
passkeys and sessions in it. CI runs it on every pull request that can affect
it, against the debug binary behind Caddy; see the `e2e` job in
[ci.yml](https://github.com/sourceorigin-dev/sourceorigin/blob/main/.github/workflows/ci.yml).

## Run it against a preview

1. Deploy this checkout and install Playwright's Chromium:

   ```console
   just preview
   pnpm exec playwright install chromium
   ```

2. Register the [clients the suite expects](#clients) on the preview, once.
3. Point the suite at the preview, then run it:

   ```console
   branch=$(git branch --show-current)
   export E2E_AUTH_URL=$(piquelctl preview url sourceorigin "$branch" --route auth)
   export E2E_ADMIN_URL=$(piquelctl preview url sourceorigin "$branch" --route admin)
   export E2E_WEB_URL=$(piquelctl preview url sourceorigin "$branch" --route web)
   export E2E_GRANT_ADMIN="piquelctl preview exec sourceorigin $branch auth -- auth-service --operator e2e admin grant"
   export E2E_RECOVER="piquelctl preview exec sourceorigin $branch auth -- auth-service --operator e2e user recover"
   export E2E_SERVER_CLIENT_SECRET=<secret>   # printed when you registered browser-e2e-server
   just web test-browser
   ```

`just web test-browser` builds the TypeScript SDK first, since
`browser-client.spec.ts` serves the built package. Extra arguments go to
Playwright, such as a spec's name: `just web test-browser admin`.

A preview sends real email and has no Mailpit, so the tests that read email are
skipped there.

## Environment variables

| Variable | What it is | Without it |
| --- | --- | --- |
| `E2E_AUTH_URL` | Auth's origin. | `http://localhost:3000` |
| `E2E_ADMIN_URL` | The admin dashboard's origin. | The dashboard tests are skipped. |
| `E2E_GRANT_ADMIN` | A command that makes the handle appended to it an administrator, such as `just auth admin grant` with the deployment's configuration. The tests append a `--reason` before the handle. | The dashboard tests are skipped. |
| `E2E_INVITE` | A command that prints a new signup link, for a deployment whose signup needs an invitation, as CI's does. Every signup runs it, with a `--reason` appended. | Signups go to `/register`. |
| `E2E_MAIL_URL` | The API origin of a [Mailpit](https://mailpit.axllent.org) that receives the deployment's email. `just auth mailpit` runs one on `http://localhost:8025`. | The tests that read email are skipped. |
| `E2E_RECOVER` | A command that runs `auth-service user recover` on the deployment. The test appends the handle, a reason and `--yes`. | The recovery test is skipped. |
| `E2E_WEB_URL` | The origin of sourceorigin.dev's web server, `apps/web`. | The web test is skipped. |
| `E2E_SERVER_CLIENT_SECRET` | The secret of the `browser-e2e-server` client. | The server SDK test is skipped. |
| `CHROMIUM_EXECUTABLE` | A Chromium to use instead of Playwright's. | Playwright's Chromium |
| `E2E_ALLOW_SELF_SIGNED_TLS` | Any value, such as `1`, accepts certificates no browser trusts, such as Caddy's local CA in CI. Only for test deployments. | Certificates must be valid. |

The commands in `E2E_GRANT_ADMIN`, `E2E_INVITE` and `E2E_RECOVER` must use the
deployment's own configuration: `user recover`, for example, derives its link
with the deployment's token digest key.

With `E2E_MAIL_URL` set, a run sends three confirmation emails, and auth sends at
most ten an hour for one IP address. Wait between reruns against one deployment.

## Clients

Several specs sign in through these clients, and fail without them. No server
runs their origins: the tests serve the clients' pages themselves.

| Client | Kind | Redirect URI |
| --- | --- | --- |
| `browser-e2e` | Public | `https://browser-e2e.test/callback` |
| `browser-e2e-sdk` | Public, trusted, pushed requests only | `https://sdk-e2e.test/callback` |
| `browser-e2e-inline` | Public, trusted, with its own origin approved for passkeys | `https://localhost:4443/callback` with auth on `localhost`, otherwise `https://related-e2e.test/callback` |
| `browser-e2e-server` | Confidential, trusted, with refresh tokens | `http://127.0.0.1:4100/auth/callback` |

`just web browser-client` registers all four with the auth database configured in
the environment, for auth on `localhost`, as CI does. It sets
`browser-e2e-server`'s secret from `E2E_SERVER_CLIENT_SECRET`: 32 random bytes in
unpadded base64url.

Previews don't register them. Register them on the preview through its CLI:

```console
cli() { piquelctl preview exec sourceorigin "$(git branch --show-current)" auth -- auth-service --operator e2e "$@" --reason 'Browser tests'; }
cli client create browser-e2e --name 'Browser E2E' \
    --redirect-uri https://browser-e2e.test/callback
cli client create browser-e2e-sdk --name 'Browser E2E SDK' --trusted --require-par \
    --redirect-uri https://sdk-e2e.test/callback
cli client create browser-e2e-inline --name 'Browser E2E inline' --trusted \
    --redirect-uri https://related-e2e.test/callback
cli client origin add browser-e2e-inline https://related-e2e.test
cli client create browser-e2e-server --name 'Browser E2E server' --trusted --confidential \
    --scope openid --scope profile --scope email --scope offline_access --refresh \
    --redirect-uri http://127.0.0.1:4100/auth/callback --post-logout-uri http://127.0.0.1:4100/
```

The last command prints the client's secret once: set `E2E_SERVER_CLIENT_SECRET`
to it.

## Limits

`oidc.spec.ts` signs up with a virtual passkey marked as backed up, so the suite
checks that auth accepts synced passkeys. It can't check Apple's or Google's
password managers, or sign-in with live Google and GitHub accounts: try those by
hand on a preview.
