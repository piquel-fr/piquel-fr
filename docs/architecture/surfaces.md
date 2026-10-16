# Auth, account and admin surfaces

piquel.fr identity is split across three hosts. Each has one job, so the login
path stays small and scales on its own while the account and admin pages grow.
This is the target design; parts not built yet are marked *(planned)*.

| Host | Serves | Used by |
| --- | --- | --- |
| `auth.piquel.fr` | OIDC/OAuth endpoints, ceremony pages and the account and admin JSON APIs | every application and user |
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

Both are SvelteKit servers on Node (adapter-node), deployed separately from
auth, so public profiles and discovery documents *(planned)* can be rendered per
request. The servers keep no state and have no database: public pages read auth's public API, and account and
admin pages call auth's JSON APIs from the browser with the auth session cookie.
The hosts are same-site, so the host-only cookie is sent without third-party
cookie exceptions. Each frontend origin is allowed exactly, and mutations still
require the CSRF header. No access token is held by these pages.

Passkeys are bound to the `auth.piquel.fr` RP ID, so passkey ceremonies always
run on auth. When an API call needs a recent passkey confirmation, auth answers
with a step-up error, and the frontend sends the user to auth to confirm and
back. Users never unlock settings explicitly. Today, settings still opens the
two-minute management window explicitly before sensitive changes.

The admin API additionally requires an administrator account signed in with a
passkey, and accepts only the admin origin (`AUTH_ADMIN_URL`); without it the API
is off. Non-administrators get the 404 of an unknown path. Mutations need a
recent passkey confirmation. Administrator rights are granted only by the CLI, and
the API never changes an administrator account, so a stolen admin session cannot
lock out other administrators. One `AdminOperations` type owns every operation;
HTTP handlers and CLI commands are thin adapters that pass the acting
administrator or operator, which each audit entry records. Administrators will be
able to change the settings of users who are not administrators, through the same
handlers as the owner, but never add a credential or email to their account
*(planned)*. Every admin operation will also exist as an `auth-service` CLI
command *(planned; today the CLI grants administrators and creates invitations)*.
admin.piquel.fr starts reachable only on the tailnet; that limits the network path
and replaces none of these checks.

## Contracts

Third-party applications integrate only through open standards: OIDC, OAuth and
their registration, discovery and token RFCs. The account and admin APIs are
first-party; they change together with the frontends in this repository.

## Recovering auth

Nothing auth runs on may require auth to log in: piqueld, server access, the
tailnet, PostgreSQL, DNS and the tunnel. If auth or its frontends are down, the
CLI, given database access, can still do every admin operation and repair
accounts.
