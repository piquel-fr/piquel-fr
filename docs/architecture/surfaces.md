# Auth, account and admin surfaces

piquel.fr identity is split across three hosts. Each has one job, so the login
path stays small and scales on its own while the account and admin pages grow.
This is the target design; parts not built yet are marked *(planned)*.

| Host | Serves | Used by |
| --- | --- | --- |
| `auth.piquel.fr` | OIDC/OAuth endpoints, ceremony pages and the JSON APIs | every application and user |
| `piquel.fr` | Account settings; security center, developer console, public profiles *(planned)* | signed-in users |
| `admin.piquel.fr` | Admin dashboard; auth's private admin API behind it | administrators |

## auth.piquel.fr

The auth executable owns everything that authenticates someone or issues a
credential: discovery, JWKS, authorization, token, userinfo, logout, and the
pages a ceremony needs (login, signup, consent, passkey confirmation, account
recovery *(planned)* and device verification *(planned)*). It never hosts settings, developer or admin pages.

The account and admin APIs are routes in the same executable. They are small
next to the pages that use them, and keeping them there keeps one binary, one
database owner and one policy layer. The account API is on the public listener; the
admin API has a private listener of its own (see admin.piquel.fr below). Auth keeps its state in PostgreSQL, so it runs
as several replicas (see "Running several replicas" in `infra/README.md`). Its sign-in pages are static assets embedded at build time
and are cacheable (see "Caching" in `infra/README.md`). Consent and logout are
server-rendered in the executable, with plain forms. Their only script is the SDK's,
which keeps the consent form from posting twice.

## piquel.fr

A SvelteKit server on Node (adapter-node), deployed separately from auth, so
public profiles and discovery documents *(planned)* can be rendered per request.
The server keeps no state and has no database: public pages read auth's public
API, and account pages call auth's JSON APIs from the browser with the auth session
cookie. The hosts are same-site, so the host-only cookie is sent without
third-party cookie exceptions. Each frontend origin is allowed exactly, and
mutations still require the CSRF header. No access token is held by these pages.

Passkeys are bound to the `auth.piquel.fr` RP ID, so passkey ceremonies always
run on auth. When an API call needs a recent passkey confirmation, auth answers
with a step-up error, and the frontend sends the user to auth to confirm and
back. Users never unlock settings explicitly.

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
`/account` routes run them as the owner of the session cookie, the only way to act
as an owner. The `auth-service account <user> …`
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
| OIDC clients | | all; administrators use `AdminService`'s |

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

### Recovering an account

An owner who lost every passkey cannot add one: adding a way to sign in needs a
passkey confirmation. `AdminService::recover_account` helps without giving the
administrator a way in. It signs the account out everywhere and emails the
owner's primary verified address a link that enrolls one passkey, once, within a
day, then signs that browser in with it. The link's token alone authorizes it;
only its digest is stored, and the email's delivery stores neither. Only an
operator at the terminal sees the link (`user recover`), which also reaches an
owner without an address. An administrator never sees it, so they may recover
only an account with a primary address; the dashboard's way to start one is
*(planned)*. A new recovery, or disabling the account, stops an unused link, and
every verified address hears when a recovery enrolls a passkey.

A recovery can be undone until its unused link expires, or for 30 days after the
link was used (`SETTLE_WINDOW`); then it settles. The window runs while the
account is disabled too, so support investigating a recovery should settle the
question within it. Undoing is a passkey ceremony of
its own (`/account/recovery/undo/start` and `/finish`), by a passkey enrolled
before every recovery that can still be undone: neither a recovery's passkey nor a
social sign-in counts, since whoever holds them may not be the owner. It needs no
session, so whoever used the link cannot stop it by signing the owner out. The
recovery's passkey sign-in counts as a fresh confirmation, so they could add more
ways in right away. Undoing therefore takes back everything the account gained
since the recovery started: it stops a link not used yet, removes every passkey
enrolled, identity linked, OIDC consent given and address added or verified
since, makes the primary address the recovery started with primary again (or the
oldest address verified before it), ends every session and signs the undoing
browser in. Revoking the consents means an app they approved cannot sign the
owner in again without asking. The owner loses what they added themselves
meanwhile too, so the undo page lists exactly what goes first. Owned clients and
profile edits stay: they are not ways in.

Until a recovery settles, a session that does not predate it cannot remove the
passkeys, identities or addresses the account had before it, nor move the primary
address away from one, so whoever used the link can neither make it impossible
to undo nor redirect the next link; administrators and operators still can. With
several recoveries to undo, only what predates all of them is trusted.

An owner with no passkey left from before a recovery cannot undo it themselves,
so support can (`user undo-recovery`, `AdminService::undo_recovery`) once it has
confirmed them: the same rollback, recorded with the reason. Starting another
recovery while a used one can be undone is refused unless asked for
(`--despite-undoable`), its link goes to the primary address the oldest undoable
recovery recorded, and `user recover` first lists each undoable recovery with
everything it added. Nobody is made an administrator while a recovery can be
undone, except by the CLI when asked for. No account is recovered while it holds administrator
rights: whoever used the link could use them before the owner undoes it, so
revoking them is the prerequisite.
The pages that use the link and offer the undo are *(planned)*; until then no page uses a link.

## Contracts

Third-party applications integrate only through open standards: OIDC, OAuth and
their registration, discovery and token RFCs. The account and admin APIs are
first-party; they change together with the frontends in this repository.

## Recovering auth

Nothing auth runs on may require auth to log in: piqueld, server access, the
tailnet, PostgreSQL, DNS and the tunnel. If auth or its frontends are down, the
CLI, given database access, can still do every admin operation and repair
accounts: see [Administration](../../README.md#administration). Recovering an
account whose owner lost every passkey follows
[account recovery](../security/account-recovery.md), including support's
evidence policy.
