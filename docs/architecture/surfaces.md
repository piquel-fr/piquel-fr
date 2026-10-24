# Auth, account and admin surfaces

piquel.fr identity spans three hosts. This is the target design; parts not built
yet are marked *(planned)*.

| Host | Serves | Used by |
| --- | --- | --- |
| `auth.piquel.fr` | OIDC/OAuth endpoints, ceremony pages, account settings, the developer console and the JSON APIs; security center *(planned)* | every application and user |
| `piquel.fr` | A redirect to auth.piquel.fr that keeps the path; public profiles *(planned)* | old links and bookmarks |
| `admin.piquel.fr` | Admin dashboard; auth's private admin API behind it | administrators |

## auth.piquel.fr

The auth executable owns everything that authenticates someone or issues a
credential: discovery, JWKS, authorization, token, userinfo, logout, and the
pages a ceremony needs (login, signup, consent, passkey confirmation, device
verification *(planned)*). It also serves the account settings at `/settings`, on
the paths piquel.fr used, and redirects its root there, and the developer console,
where accounts register their own OIDC clients, at `/developers`. It hosts no admin
pages yet.

The account and admin APIs are routes in the same executable. They are small
next to the pages that use them, and keeping them there keeps one binary, one
database owner and one policy layer. The account API is on the public listener; the
admin API has a private listener of its own (see admin.piquel.fr below). Auth keeps its state in PostgreSQL, so it runs
as several replicas (see "Running several replicas" in `infra/README.md`). Its sign-in pages are static assets embedded at build time
and are cacheable (see "Caching" in `infra/README.md`). Consent, logout, the
settings and the developer console are server-rendered in the executable, with
plain forms. Their only script
is the SDK's, which runs the passkey ceremonies their forms need and keeps a form
from posting twice.

Passkeys are bound to the `auth.piquel.fr` RP ID, so passkey ceremonies always
run on auth. A settings change that needs a recent passkey confirmation asks for
it on its page before the form posts. Users never unlock settings explicitly.

## piquel.fr

piquel.fr runs no service: the gateway redirects it to auth.piquel.fr with a
temporary `307`, keeping the path and query, and browsers keep the fragment. Links
to `piquel.fr/settings/…` sent before the settings moved still open the same page.
The security notices among them never expire, so the redirect stays until
piquel.fr serves pages of its own, such as public profiles *(planned)*.

## admin.piquel.fr

The admin dashboard (`apps/admin-web`) is a server-rendered Rust app on Topcoat,
reachable only on the tailnet. It signs administrators in as the confidential OIDC
client `piquel-admin`, with the Rust SDK's login routes, and keeps their tokens in
its server's memory; the browser holds only the dashboard's session cookie. Its
server calls the admin API with the administrator's access token, through the typed
client in `piquel-admin-api`, so both sides share one definition of the API. Pages
that change something confirm a recent passkey before showing their form, so the
administrator steps up before submitting rather than after.

Auth serves the admin API on a second, private listener that no ingress route
reaches, so neither the internet nor the tailnet can call it; only the
application's own services can. The network path is a second wall, not the
authorization. Auth checks every call:

- The token is for `piquel-admin`, and comes from a passkey sign-in.
- Its account is an administrator, and its session is still active. Both are read
  on each call, so revoking either takes effect at once.
- A mutation needs a passkey confirmation from the last five minutes. Otherwise
  auth answers with an RFC 9470 challenge, and the dashboard sends the
  administrator through auth's login and back.

Administrators manage the administrator list too, but never their own rights or
the last administrator's, and the API never changes an administrator's account.
Every admin operation is also an `auth-service` CLI command; granting the first
administrator is one.

### Changing an account on its owner's behalf

Administrators change other users' settings with the owner's own operations,
never by signing in as them. Each setting an administrator may share with the
owner is an `AccountService` operation: a change takes a `Subject`, the account and
who acts on it, and a read a `Viewer`, the account and who reads it. The owner's
settings pages and `/account` routes run them as the owner of the session cookie,
the only way to act as an owner. The `auth-service account <user> …`
command runs them as the operator at the terminal, and the dashboard will call
them in-process as an administrator *(planned)*. Both run the same safety rules:
for example, one active passkey always remains, whoever removes the others.

The rule for what is shared: administrators may view, edit and remove, but never
add a way to sign in or to receive the account's email, since that would let them
take the account over. The operations only the owner may run take an `Owner`,
which only the session cookie builds, or for a client the `OwnedClient` built from
one, so calling one for an administrator does not compile. Two owner-only actions
are authorized otherwise: verifying an address by its link's token, so it works
signed out, and confirming with a passkey by the session it confirms.

| Area | Shared | Owner only |
| --- | --- | --- |
| Passkeys | list, rename, remove | add, confirm |
| Social identities | list, unlink | link |
| Email addresses | list, choose the primary among verified, remove | add, verify |
| Sessions | list, sign out one, sign out all | |
| Security history | read | report an entry |
| OIDC clients (the developer console) | | all; administrators use `AdminService`'s |

When an administrator or operator acts:

- Every change needs their reason. It is stored with each event as personal data,
  and the owner sees it in their security history, next to "By a Piquel
  administrator".
- Events record the administrator or operator as their actor. A read is recorded
  as a view of the account, as `user show` is.
- An administrator may not change another administrator's account: it is refused
  before waiting for the account lock and again under it. A change checks the
  administrator's rights, session and passkey confirmation once more before it
  commits. The CLI may change administrators' accounts.
- A change that signs the owner out elsewhere, such as removing a passkey, signs
  out every session, since an administrator has none of the owner's to keep.

## Contracts

Third-party applications integrate only through open standards: OIDC, OAuth and
their registration, discovery and token RFCs. The account and admin APIs are
first-party; they change together with the frontends in this repository.

## Recovering auth

Nothing auth runs on may require auth to log in: piqueld, server access, the
tailnet, PostgreSQL, DNS and the tunnel. If auth or its frontends are down, the
CLI, given database access, can still do every admin operation and repair
accounts: see [Administration](../../README.md#administration).
