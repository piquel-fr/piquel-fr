# admin-web

The admin dashboard at `admin.piquel.fr`: a server-rendered Rust app on
[Topcoat](https://github.com/tokio-rs/topcoat) for looking up accounts, reviewing
their sessions and history, and changing them. Pages render on the server, with no
client JavaScript. It is reachable only from the tailnet.

The dashboard is a convenience: every operation is also an `auth-service` command
(`just auth admin`, `just auth invite`), and recovery never depends on it.

## How it works

- **Sign-in.** The dashboard is the confidential OIDC client `piquel-admin`,
  registered as trusted, so administrators skip consent. The Rust SDK's login
  routes (`/auth/login`, `/auth/callback`, `/auth/logout`) and session layer wrap
  the Topcoat pages. Tokens stay in the server's memory; the browser holds only
  the `__Host-` session cookie. A restart signs administrators out of the
  dashboard, and signing in again is silent while their auth session lasts.
- **The admin API.** Pages call auth's private admin API (`ADMIN_API_URL`) with the
  administrator's access token, through the typed client in `crates/admin-api`.
  The dashboard has no database credentials. A non-administrator sees "This
  account has no access", the API's `403`, and nothing else.
- **Step-up.** Pages that change something require a passkey confirmation from the
  last three minutes before showing their form, so it still meets the API's five
  minutes when the form is submitted. Without one, the SDK sends the administrator
  through auth's login and back to the same page. A step-up challenge from the API
  is answered the same way; a form it refused is then submitted again.
- **Changes.** Each change has its own page: a `GET` shows the form, and only a
  `POST` from the dashboard's own pages makes the change. No page can be framed or
  cached. Changes the API refuses for administrator accounts are shown disabled,
  with the reason.

| Page | Content and actions |
| --- | --- |
| `/users` | Search by username, display name, email or ID |
| `/users/{id}` | Profile, emails, passkeys, identities, sessions, consents, recent events; disable, enable, revoke one or all sessions |
| `/administrators` | List, grant, revoke |
| `/invitations` | While signup requires invitations: list, create (the link is shown once), revoke |
| `/clients` | Every OIDC client and its settings, read-only |
| `/events` | Domain events, filtered by account and kind |

## Configuration

| Variable | Meaning |
| --- | --- |
| `ADMIN_AUTH_ORIGIN` | Auth's issuer, e.g. `https://auth.piquel.fr` |
| `ADMIN_API_URL` | The admin API on auth's private listener, e.g. `http://auth:8081` |
| `ADMIN_ORIGIN` | The dashboard's own origin, e.g. `https://admin.piquel.fr`. Sign-in returns to its `/auth/callback`, sign-out to its root; both must be registered for `piquel-admin` |
| `ADMIN_CLIENT_SECRET` | Reference to the `piquel-admin` client secret, `file://PATH` or `env://NAME` |
| `ADMIN_LISTENER` | Listener address; defaults to `127.0.0.1:3001` |

The dashboard discovers auth in the background, retrying until it answers, so it
starts and passes its health check (`GET /healthz`) while auth comes up. Until
then, pages answer `503`.

## Development

Run it on a preview: `just preview` deploys it with auth, and prints its URL,
`https://admin-<slug>.dev.piquel.fr`. Grant your preview account administrator
rights first (see `infra/README.md`). `just admin serve` runs it with your own
`ADMIN_*` configuration, which needs an HTTPS auth whose private listener it can
reach.
