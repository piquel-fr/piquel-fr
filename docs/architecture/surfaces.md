# Auth, account and admin surfaces

piquel.fr identity is split across three hosts. Each has one job, so the login
path stays small and scales on its own while the account and admin pages grow.
This is the target design; parts not built yet are marked *(planned)*.

| Host | Serves | Used by |
| --- | --- | --- |
| `auth.piquel.fr` | OIDC/OAuth endpoints, ceremony pages and the JSON APIs | every application and user |
| `piquel.fr` | Account settings; security center, developer console, public profiles *(planned)* | signed-in users |
| `admin.piquel.fr` | Admin dashboard *(planned)* | administrators |

## auth.piquel.fr

The auth executable owns everything that authenticates someone or issues a
credential: discovery, JWKS, authorization, token, userinfo, logout, and the
pages a ceremony needs (login, signup, consent, passkey confirmation, device
verification *(planned)*). It never hosts settings, developer or admin pages.

The account and admin APIs are routes in the same executable. They are small
next to the pages that use them, and keeping them there keeps one binary, one
database owner and one policy layer. Auth stores no state outside PostgreSQL, so
replicas scale horizontally. Its pages are static assets embedded at build time
and are cacheable.

## piquel.fr and admin.piquel.fr

Both are static frontends deployed separately from auth. They call auth's JSON
APIs from the browser with the auth session cookie. The hosts are same-site, so
the host-only cookie is sent without third-party cookie exceptions. Each frontend
origin is allowed exactly, and mutations still require the CSRF header. No access
token is held by these pages.

Passkeys are bound to the `auth.piquel.fr` RP ID, so passkey ceremonies always
run on auth. When an API call needs a recent passkey confirmation, auth answers
with a step-up error, and the frontend sends the user to auth to confirm and
back. Users never unlock settings explicitly. Today, settings still opens the
two-minute management window explicitly before sensitive changes.

The admin API *(planned)* additionally requires an administrator account and
accepts only the admin origin. Every admin operation also exists as an
`auth-service` CLI command.

## Contracts

Third-party applications integrate only through open standards: OIDC, OAuth and
their registration, discovery and token RFCs. The account and admin APIs are
first-party; they change together with the frontends in this repository.

## Recovering auth

Nothing auth runs on may require auth to log in: piqueld, server access, the
tailnet, PostgreSQL, DNS and the tunnel. If auth or its frontends are down, the
CLI, given database access, can still do every admin operation and repair
accounts.
