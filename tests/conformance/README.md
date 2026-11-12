# OpenID conformance suite

`just conformance` runs the OpenID Foundation's
[conformance suite](https://gitlab.com/openid/conformance-suite) against Origin
Auth and compares every result with [`expected.json`](expected.json). It checks
auth against the specifications themselves, where auth's own tests check only
our reading of them. CI runs it too.

It runs these plans, from [`plans.json`](plans.json):

| Plan | What it checks |
| --- | --- |
| `oidcc-basic-certification-test-plan` | Sign-in with the code flow, discovery and static clients |
| `oidcc-config-certification-test-plan` | The discovery document |
| `oidcc-rp-initiated-logout-certification-test-plan` | RP-Initiated Logout |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | Back-Channel Logout |

The suite runs in Docker, from its prebuilt image, or, to test a release, on the
Foundation's own hosted suite. Its own browser can't create
passkeys, so [`driver.ts`](driver.ts) plays the browser's part in Chromium with
a virtual passkey, as the [browser tests](../browser/README.md) do. It signs an
account up, then, for every test, opens each page the suite asks for, signs in,
approves consent, confirms logout, and gives the suite the screenshots it asks
for.

## Run it

You need Docker on Linux, since the containers share the host's network, and
Playwright's Chromium:

```console
pnpm exec playwright install chromium
just conformance
```

The recipe builds auth and starts it at `https://localhost:7443`, with its own
PostgreSQL and Mailpit, behind [Caddy](Caddyfile). It registers the suite's
clients and runs every plan. A run takes about 15 minutes, and prints each
test's result, with the reason for any that didn't pass. It fails if any result
differs from `expected.json`.

These ports must be free: 8443 and 7443 (Caddy), 8080 (the suite), 27017
(its MongoDB), 7432 (PostgreSQL), and 7025 and 7026 (Mailpit).

To run a few tests while you work on them, name them:

```console
CONFORMANCE_TESTS=oidcc-server,oidcc-prompt-login just conformance
```

Only the tests you name are compared then.

### Test a release

Before promoting staging to production, test its release on the OpenID
Foundation's own hosted suite at <https://www.certification.openid.net>, the one
certification uses:

```console
export CONFORMANCE_SUITE_TOKEN=file:///path/to/token
just conformance release
```

1. The recipe finds staging's current deployment, and reads `plans.json` and
   `expected.json` from the commit it was built from.
2. It promotes that release into the `conformance` environment, which makes it
   public at `https://auth-conformance.sourceorigin.dev`. piquelctl shows what it
   deploys and asks first.
3. It registers the suite's clients and a test account through the environment's
   CLI, runs every plan on the hosted suite, and compares the results.
4. It stops the environment, whatever happened, so it is public only while the
   run lasts.
5. If every result matched, it offers to promote the same deployment to
   production, and piquelctl asks again. Otherwise it stops there.

The token is the hosted suite's API token: sign in at
<https://www.certification.openid.net/login.html> with Google or GitLab, then
create a permanent token at
<https://www.certification.openid.net/tokens.html>. Keep it in a file outside the
repository, and point `CONFORMANCE_SUITE_TOKEN` at it, as `file:///path` or
`env://NAME`.

You need `piquelctl` with `apps:deploy` and `apps:exec` on `sourceorigin`, and the
`conformance` environment needs the `resend-dev` secret, granted once:

```console
piquelctl app secret sourceorigin access resend-dev --environments staging,conformance --previews
```

The account has no email address, since the run can't read the environment's
email, so `oidcc-scope-email` isn't compared. The plans stay in your account on
the hosted suite, where
[certification](https://github.com/sourceorigin-dev/sourceorigin/issues/52) can
use them.

### Against a preview

The suite reaches the preview from your machine, which must be on the tailnet.
The driver registers clients and invitations through the preview's CLI:

```console
branch=$(git branch --show-current)
export CONFORMANCE_CLI="piquelctl preview exec sourceorigin $branch auth -- auth-service --operator conformance"
just conformance "$(piquelctl preview url sourceorigin "$branch" --route auth)"
```

Two parts can't run there. The back-channel logout plan is skipped: the
preview's logout tokens can't reach the suite on your machine. The account has
no email address, since the driver can't read the preview's email, so
`oidcc-scope-email` isn't compared.

## Results

Everything a run produces goes to `target/conformance`, which CI uploads as the
`conformance` artifact:

- `results.json`: each test's result.
- `<plan>.zip`: each plan's full logs, as the suite exports them.
- `screenshots/`: the screenshots the suite asked for, by test.
- `auth.log` and `compose.log`: what auth and the containers logged.

While a local run lasts, the suite's own pages at `https://localhost:8443` show
each test's log. The driver prints each plan's link.

## `expected.json`

`expected.json` lists every test whose result isn't `PASSED`, by name:

```json
{
  "oidcc-userinfo-post-body": {
    "result": "WARNING",
    "reason": "UserInfo reads the access token only from the Authorization header.",
    "issue": "https://github.com/sourceorigin-dev/sourceorigin/issues/515"
  }
}
```

- `result` is what the suite reports: `FAILED`, `WARNING`, `REVIEW` or
  `SKIPPED`.
- `reason` says why, in one line. For a `REVIEW`, it says what the reviewer must
  see in the test's screenshot.
- `issue` links the issue that fixes it. A deviation certification accepts, such
  as a screenshot every certification reviews, links
  [#52](https://github.com/sourceorigin-dev/sourceorigin/issues/52).

A test's result must equal its entry, or be `PASSED` when it has none. Anything
else fails the run, including an unexpected `PASSED`, so the file only shrinks:
a pull request that fixes a deviation removes its entry. `UNKNOWN`, a test that
never finished, always fails.

When a change alters a result on purpose, update the entry in the same pull
request, and look at the test's screenshot if it has one.

## Update the suite

The suite's version is pinned in [`docker-compose.yml`](docker-compose.yml). To
update it, change the `release-v…` tag of its image to a newer
[release](https://gitlab.com/openid/conformance-suite/-/tags), run
`just conformance`, and update `expected.json` for any test the new release
added or changed.

## Environment variables

The recipe sets them for a local run. Against a preview, set
`CONFORMANCE_CLI` yourself.

| Variable | What it is |
| --- | --- |
| `CONFORMANCE_CLI` | A command that runs `auth-service` with the deployment's configuration. The driver appends its arguments. |
| `CONFORMANCE_SUITE_TOKEN` | For `release`: where the hosted suite's API token is, as `file:///path` or `env://NAME`. |
| `CONFORMANCE_TESTS` | Comma-separated test names to run instead of every test. |
| `CONFORMANCE_OUTPUT` | Where the results go, instead of `target/conformance`. |
| `CHROMIUM_EXECUTABLE` | A Chromium to use instead of Playwright's. |

A local run also starts auth with `AUTH_LOOPBACK_LOGOUT_CA`, so its back-channel
logout tokens reach the suite on `localhost`. Never set it in a deployment.
