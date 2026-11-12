# Auth, account and admin surfaces

This page sets out what each of SourceOrigin's three hosts serves, and how
administrators act on accounts without signing in as their owners. Parts not
built yet are marked *(planned)*.

| Host | Serves | Used by |
| --- | --- | --- |
| `auth.sourceorigin.dev` | OIDC/OAuth endpoints, ceremony pages, account settings, the developer console and the JSON APIs; security center *(planned)* | every application and user |
| `sourceorigin.dev` | Its own web server: the homepage and SourceOrigin's policies, and a redirect to auth.sourceorigin.dev that keeps every other path; public profiles *(planned)* | visitors, old links and bookmarks |
| `admin.sourceorigin.dev` | The admin dashboard, which auth serves on a listener of its own | administrators |

## auth.sourceorigin.dev

The auth executable owns everything that authenticates someone or issues a
credential: discovery, JWKS, authorization, token, userinfo, logout, and the
pages a ceremony needs (login, signup, consent, passkey confirmation, account
recovery at `/recover` and `/recover/undo`, device verification *(planned)*). It
also serves the account settings at `/settings`, an overview first, then the
inbox at `/settings/notifications`, the sign-in methods at `/settings/sign-in` and
the other pages on the paths
sourceorigin.dev used, and redirects its root there, and the developer console, where
accounts register their own OIDC clients, at `/developers`. The admin dashboard is the same
executable too, on another listener and host (see admin.sourceorigin.dev below).

The account API is routes in the same executable. It is small next to the pages
that use it, and keeping it there keeps one binary, one database owner and one
policy layer per listener. Auth keeps its state in PostgreSQL, so it runs
as several replicas (see [running several replicas](../operations/replicas.md)). Every page it
serves, sign-in, consent, logout, account recovery, the settings and the
developer console, is server-rendered in the executable, with plain forms, and
never cached. Their scripts are the passkey script, which runs the passkey
ceremonies their forms need and keeps a form from posting twice, the picture
script, which lets the picture form choose its crop, the search script, and
the copy script, whose buttons, and the values beside them, copy a value such as
a client secret or a signup link to the clipboard.

The search script ranks the top bar's results as the user types. Every signed-in
page holds its area's pages, settings and actions as results
(`crates/ui/src/layout/search.rs`), so ranking them needs no request. Each comes
from what renders or routes it, never a copied link: the sidebar's tabs, the
settings' `Part`s, whose IDs their headings take, the profile's dialogs, by the
query opening them, the account's apps, and the dashboard's `SearchAction`s, by their
routes. On the dashboard, the script also fetches `/search?q=` once a query
has two letters, unless a shorter query it contains found nothing. It answers
with the accounts and clients the query finds, in the same markup, and spends a
budget of its own (see [rate limit](request-lifecycle.md#rate-limit)). A search field marked
`data-live` refreshes its form's results as the user types, by submitting the
form in the background and swapping in the regions it names; on the dashboard,
these refreshes spend the search budget too. Without the
script, the dashboard's search goes to **Users**, and the settings' search is
hidden: the sidebar still reaches every page.

Passkeys are bound to the `auth.sourceorigin.dev` RP ID, so passkey ceremonies always
run on auth. A settings change that needs a recent passkey confirmation asks for
it on its page before the form posts. Users never unlock settings explicitly.

## sourceorigin.dev

sourceorigin.dev is its own product, served by its own web server, `apps/web`. It relies
on auth only to sign people in: it links auth's pages and never shares auth's
database, keys or process. Today it serves the homepage, which says what SourceOrigin's
sign-in is and links each surface, the privacy policy at `/privacy` and the terms
of service at `/terms`. They are static, with no session, form or script, and the
only pages search engines may index. Auth links the policies there
(`AUTH_WEB_ORIGIN`): every auth page's footer does, the dashboard's included, and
so does the registration form, which agrees to them. OIDC discovery advertises
them as `op_policy_uri` and `op_tos_uri`, which the SDK reads with the rest of the
metadata.

Every other path redirects to the same one on auth.sourceorigin.dev, with a temporary
`307` keeping the path and query; browsers keep the fragment, so links to
`sourceorigin.dev/settings/…` open the same page on auth. The security notices among
them never expire, so the redirect stays until
sourceorigin.dev serves pages of its own at those paths, such as public profiles
*(planned)*.

## admin.sourceorigin.dev

Auth serves the admin dashboard itself, on its admin listener
(`AUTH_ADMIN_LISTENER`), for the dashboard's own origin (`AUTH_ADMIN_ORIGIN`). Only
a private route reaches that listener, so the dashboard is reachable only on the
tailnet. Its pages are server-rendered in `apps/auth-service/src/web/admin`,
render the views of `sourceorigin_common::admin` with `sourceorigin-ui`'s dashboard
components, and call `AdminService` in-process, as the CLI does, and
`AccountService` for an account's settings (see below): there is no admin API.
The network path is a second wall, not the authorization.

The admin listener has a security layer of its own. It answers only requests that
name the dashboard's host, takes a form only from the dashboard's own pages (the
same-origin rule auth's pages follow), spends a request budget of its own, and
limits bodies to 512 KiB, which an announcement's text and accounts need. Every
page loads only the stylesheet, the dashboard's own script, the search script
and the copy script, which its Content-Security-Policy names alone, and its forms post only
to the dashboard, whose answer may go on to auth's handoff page.

The dashboard is no OIDC client. An administrator signs in by a handoff from auth:

1. A browser without a dashboard session, or whose change needs a confirmation, is
   sent to auth's handoff page, `/admin`, with a state the dashboard keeps in a
   cookie of its own origin.
2. The handoff page needs a session signed in with a passkey, of an account that
   still holds administrator rights: anyone else is told they have no access, and
   a social sign-in signs in with a passkey first. It then asks for a passkey, in
   a ceremony started for the handoff, every time: a browser left signed in to
   auth cannot open the dashboard without the administrator. It sends the browser
   back with a code that works once, for 60 seconds, bound to that session and to
   the state.
3. The dashboard redeems the code in the browser holding the state, and starts a
   session of its own, storing only its cookie's digest, with the auth session and
   the passkey's proof as its confirmation.

The dashboard's session rests on the auth session: signing out of auth, revoking
that session or replacing it ends it, and every request checks the
administrator's rights again. It also ends after 30 minutes without a request,
12 hours after its sign-in however busy, and when the account's administrator
rights are revoked, in the same transaction, with the handoffs that would start
one: rights granted again revive none. Writing a handoff or redeeming one holds
the rights, as a change does, so a revocation waits for it and then ends what it
wrote, or comes first and refuses it. Signing out of the dashboard ends only its
session. Signing in and out are recorded as `dashboard_signed_in` and
`dashboard_signed_out`, which the administrator's security history shows; a
session that times out records nothing. A confirmation on auth's handoff page,
where the dashboard's script cannot confirm on the page, signs in again: it
records another sign-in, and the new session's 12 hours start from it, since a
passkey proved it. The account's devices list each dashboard session under the
auth session it rests on, with its last use.
[The admin dashboard's session](sessions.md#the-admin-dashboards-session) describes
how it is stored.

A change needs the dashboard's own passkey confirmation from the last five
minutes, which a confirmation for auth's pages never gives, and signing in gives.
A page that changes something sends the browser to the handoff page to confirm
before showing its form: there, a passkey proves the handoff in a ceremony
started for it, recorded as `passkey_confirmed`, and the dashboard keeps that
time as its confirmation. The auth session's own
confirmation stays as it was. Once confirmed, a short change such as revoking a
session confirms in a dialog on the list page itself, which the browser opens
and closes with no script (`popovertarget`), posting to the change's own page;
a dashboard not confirmed yet links that page instead, which confirms first.

The dashboard's script spares the browser that trip: before following a link to a
page that confirms first, or posting a change once the confirmation is too old, it
asks for a passkey in a dialog on the page, then goes on to the change. Each page's
frame says how long its confirmation lasts. The dialog runs the ceremony for auth's
RP ID on the dashboard's own origin, which auth's `/.well-known/webauthn` lists as
a related origin (`WebAuthn` Level 3 §5.11), against the dashboard's `/confirm`
routes. The proof is the handoff's kind: started by the dashboard session's auth
session, bound to the browser, signed for the dashboard's origin, which the
handoff refuses, and kept as the dashboard's confirmation only. The dialog names
what it confirms, from the link's or form's `data-confirming`: the change, and
what it acts on. The script also posts each change's form once, so a double
click makes no second change. Without the script, or in a browser without
related origins, the browser goes to the handoff page and back as before.

Every change goes through `AdminApplication::change`, which keeps a change from
being misread:

- **Its target.** A change's page names what it acts on beside its button, such
  as the account's handle and ID, so two pages left open cannot be told apart
  only by their address. The account or client comes from the crumb's parent.
  The passkey dialog names it too, from the account's own page as well.
- **Its status.** A refused change shows its form again with the refusal's
  status, such as `400`, not `200`.

An account's page acts only on that account: revoking a session another
account holds is not found, from the dashboard and from `session revoke`, which
names the account too.

Lists page by number, with their totals, as the CLI's `--page` does.

Administrators also send announcements, such as a security incident or a change
to the privacy policy, to every account or to chosen ones. An announcement starts
as a draft with a page of its own, showing its email as it will be sent. Drafting,
editing and discarding one need only what a read needs, since nobody else sees a
draft: a confirmation that runs out while the text is written sends the browser
to confirm and back to the saved draft, with nothing lost. Sending it needs the
dashboard's recent confirmation, like any change, and names the draft's revision
its page showed, so a draft changed meanwhile is checked again rather than sent
unseen; its text never changes afterwards. Each recipient gets it as a
notification in their inbox, and each with a primary verified address is emailed
it, unless they turned announcements' email off and it is not essential, which
its sender chooses on the draft (see
[the delivery queue](delivery-queue.md#announcements)).

Administrators also message one account, such as to say why it was disabled. A
message has no draft: the account's page links a form whose text, once written,
shows as its email will be sent, and sending it needs the dashboard's recent
confirmation. Writing and previewing need none, so the text is never lost to a
confirmation that ran out while it was written, as long as the dashboard's
script asks for one before sending. Unlike the dashboard's changes, a message
also goes to an administrator's account, since it changes nothing about it (see
[message an account](../operations/administration.md#message-an-account)).

Administrators also invite people, whether or not signup needs an invitation:
with signup open, an invitation is a tracked signup link. An invitation mailed to
an address binds the account created with it to that address, which starts
verified and primary, since opening the mailed link proves what a verification
email would. `AdminService::create_invitation` holds the rule for both surfaces:
it refuses a mailed invitation before anything changes while email is disabled,
or when an active account holds the address verified. Its link's token is
derived from its ID, so the email sender, and **Resend**, rebuild the link and
nobody sees it; one without an address is shown once instead (see
[invite someone](../operations/administration.md#invite-someone) and
[the delivery queue](delivery-queue.md#invitations)). Signup checks and redeems
any invitation it is given, whatever the setting, and records
`invitation_redeemed` with the new account.

Administrators also follow alerts: conditions auth's background jobs find that
need their attention, such as a broken audit chain. The dashboard's **Alerts**
page lists the current ones, on which administrators post status updates until
each clears, and links those that cleared; `auth-service alerts` does the same
(see [respond to an alert](../operations/administration.md#respond-to-an-alert)).
Raising an alert notifies every active administrator, in their inbox and by
email. While an alert has no update yet, the overview's banner, the sidebar's
dot and the top bar's count point to the page.

Administrators manage the administrator list too, but never their own rights or
the last active administrator's, and the dashboard never changes an administrator's
account. Nothing, the CLI included, disables or deletes the last active
administrator's account either. Every admin operation is also an `auth-service` CLI command; granting the
first administrator is one.

### Changing an account on its owner's behalf

Administrators change other users' settings with the owner's own operations,
never by signing in as them. Each setting an administrator may share with the
owner is an `AccountService` operation: a change takes a `Subject`, the account and
who acts on it, and a read a `Viewer`, the account and who reads it. The owner's
settings pages and `/account` routes run them as the owner of the session cookie,
the only way to act as an owner. The `auth-service account <user> …`
command runs them as the operator at the terminal, and the dashboard's display
name, sign-in methods, profile picture, email addresses, connected apps,
security history and notifications pages call them in-process as an
administrator, rendering the owner's own settings sections without what adds a
way in, and asking for a reason with each change. All run the same safety
rules: for example, one active passkey always remains, whoever removes the
others.

The rule for what is shared: administrators may view, edit and remove, but never
add a way to sign in or to receive the account's email, since that would let them
take the account over. The operations only the owner may run take an `Owner`,
which only the session cookie builds, or for a client the `OwnedClient` built from
one, so calling one for an administrator does not compile. Three owner-only
actions are authorized otherwise: verifying an address by its link's token, so it
works signed out, turning announcements' email off by an email's unsubscribe
link, likewise, and confirming with a passkey by the session it confirms.

| Area | Shared | Owner only |
| --- | --- | --- |
| Display name | change | |
| Passkeys | list, rename, remove | add, confirm |
| Profile picture | view, remove | set |
| Social identities | list, unlink | link |
| Email addresses | list, choose the primary among verified, remove | add, verify |
| Sessions | list, sign out one, sign out all | |
| Connected apps | list, remove an app's access | |
| Security history | read | report an entry |
| Notifications | list, read, view email preferences | mark read or unread, change email preferences |
| Account data | | download |
| OIDC clients (the developer console) | | all; administrators use `AdminService`'s |

Downloading the account's data stays the owner's although administrators may
read most of it: the export copies the account's IP addresses and every event
about it out of auth in one file, which only the owner's recently confirmed
session receives.
Support never hands one over; an owner who lost every passkey is recovered
first, and downloads it themselves.

When an administrator or operator acts:

- Every change needs their reason, on the dashboard and at the terminal alike:
  changes to accounts, and to clients, keys, invitations, handles, deliveries,
  alerts and the audit history too. `AdminService` takes it by type, so no
  change records an event without one. It is stored with each event as
  personal data, and the owner of an account it changes sees it in their
  security history, next to "By a SourceOrigin administrator". The owner never
  sees who that administrator is, or the IP address and device of their
  request: only the dashboard's event lists and `audit list` show them. Announcements
  and messages to one account ask for none: their text says why, so sending
  one records "See message contents", and a draft's own changes record
  nothing.
- Events record the administrator or operator as their actor. Their reads are
  recorded as a view of the account, as `user show` is, once an hour per
  administrator session or operator. The owner's history leaves views out: it
  shows changes, with their reasons, not reads. The dashboard's event lists and
  `audit list` leave them out too, unless "Show views" or `--views` asks for
  them, or the kind filter is `account_viewed`.
- The dashboard's event lists and `audit list` show each event's reason and who
  caused it: an administrator by their handle, linked on the dashboard, and an
  operator by name and host. The dashboard describes each known kind in words,
  with the request's device and IP address, or says retention or a purge erased
  them. `audit list --json` carries the same view, `EventPage`.
- An administrator may not change another administrator's account: it is refused
  before waiting for the account lock and again under it. A change checks the
  administrator's rights, session and passkey confirmation once more before it
  commits. The CLI may change administrators' accounts.
- A change that signs the owner out elsewhere, such as removing a passkey, signs
  out every session, since an administrator has none of the owner's to keep.

### Recovering an account

An owner who lost every passkey cannot add one: adding a way to sign in needs a
passkey confirmation. `AdminService::recover_account` helps without giving the
administrator a way in. It signs the account out everywhere, removes its
unverified addresses, and emails its current primary verified address a link
to `/recover`, which enrolls one passkey, once, within a day, then signs that
browser in with it. The link's token alone authorizes it; only its digest is
stored, and the email's delivery stores neither. Only an operator at the
terminal sees the link (`user recover`), which also reaches an owner without an
address. An administrator never sees it, so they may only start a recovery that
mails it, from the dashboard's Recover page; one that also revokes every way in
(`--revoke`) prints its link, so it stays at the terminal.

For 15 days after the link is used, the recovery is in probation: its passkey
signs in like a social login and never confirms the session. Every change that
needs a confirmation refuses it, and so do the dashboard and relying parties
that ask for `phr`, so whoever used the link can use the account but add no way
into it. Undoing the recovery takes back its passkey, every session and refresh
grant, and every app consent. The owner undoes it with any other passkey on
`/recover/undo`, which the recovery's emails link to, in a ceremony of its own
that needs no session and works on a disabled account
(`/account/recovery/undo/start` and `/finish`). Until it settles, nobody removes
a passkey but the recovery's own, administrators and operators included, so
nothing takes that away. Support undoes it for an owner with no other passkey,
from the dashboard's Undo recovery page or with `user undo-recovery`
(`AdminService::undo_recovery`). While a recovery can be undone, every settings
and developer console page, and a passkey sign-in that continues to an app, asks
"Was this you?" and links to the undo page.

`user recover --revoke` is for an account that was in someone else's hands: it
also revokes every passkey the owner doesn't vouch for, unlinks every identity
and withdraws every consent, and only prints the link. No account is recovered
while it holds administrator rights, and none is made an administrator while a
recovery of it can be undone. [Account recovery](../security/account-recovery.md)
states the policy and support's evidence policy.

## Profile pictures

An account may have one profile picture, which apps receive as the `picture`
claim under the `profile` scope, in ID tokens, access tokens and UserInfo, and
which every avatar shows in place of the initials: the account's sidebar and top
bar, and the dashboard's account lists and pages. The SDKs read it as
`SignedIn::picture()` in Rust and `user.picture` in TypeScript, and the admin
views of accounts and administrators (`sourceorigin_common::admin`), which the dashboard
shows and the CLI prints as JSON, carry its ID. The owner sets it on the settings' Profile tab, which
shows the account as apps do, with its handle, display name and picture, each
changed in a dialog the popover API opens with no script; the picture's is a
`multipart/form-data` form. There the picture script shows the chosen image under
a circle, as apps show it, to drag and zoom; the form sends the square under the
circle in the image's upright pixels (`crop_x`, `crop_y`, `crop_size`), and
without the script auth keeps the centred square. `PUT /account/picture` sets it
too, taking the square as `?x=…&y=…&size=…`. Administrators
may view and remove it, with a reason, such as one that impersonates someone,
but never set one; their Profile tab links the dashboard's own pages for the
name and the handle.

- **Only auth's own image.** Auth decodes an upload of at most 10 MiB, a PNG, JPEG
  or GIF recognized by its content, one at a time per replica. It refuses one
  whose header declares more than 8192 pixels on a side or 24 megapixels, or
  whose decoded image is over 96 MiB, before decoding it, and bounds what the
  decoder allocates. It turns the image upright from its EXIF orientation, crops
  it to the square the owner chose, or its centred square, before scaling it to
  512 pixels, flattens transparency
  onto white and encodes a JPEG of at most 128 KiB. The upload itself is never
  stored, so no metadata, such as a photo's location, survives. JPEG because
  every consumer of `picture` reads it, and the `image` crate's WebP encoder is
  lossless only, several times larger. WebP uploads are refused until its decoder
  checks a frame's size against the canvas it declares before decoding it.
- **Stored in PostgreSQL**, in `profile_pictures`, one row per account, which the
  account's purge removes with it. At about 50 KiB a picture, auth needs no object
  store until pictures dominate the database.
- **Served at `/pictures/{id}`**, by the ID of its upload: a new picture gets a new
  ID and URL, and setting or removing one bumps `profile_version`. The image at a
  URL never changes, so it is cached as immutable, for a year, with
  `Access-Control-Allow-Origin: *`. The path has no file extension, so the
  edge keeps no copy of its own: once replaced or removed, or once its account is
  disabled or scheduled for deletion, a picture's URL answers `404` at once. Its
  requests have a rate budget of their own. A random ID rather than the content's
  hash, since a hash would let anyone holding an image check whether an account
  uses it, and re-encoding leaves nothing to deduplicate.
- **Imported at a social signup.** An account created with GitHub or Google
  starts with the picture the provider reported: GitHub's avatar, or Google's
  `picture` claim, asked for at 512 pixels. Only a URL on the provider's own
  picture host is kept, with the signup's pending evidence. Once the account is
  committed, auth fetches it once, off the signup's request, with the client
  deliveries use, which reaches only public addresses and follows no redirect,
  asking only for the formats it reads, and encodes it as an upload. A picture
  that cannot be fetched or encoded is logged; the signup has already
  succeeded. Later sign-ins import nothing, so a removed picture stays removed.

## Contracts

Third-party applications integrate only through open standards: OIDC, OAuth and
their registration, discovery and token RFCs. The account API is first-party; it
changes together with auth's pages in this repository.

## Recovering auth

Nothing auth runs on may require auth to log in: piqueld, server access, the
tailnet, PostgreSQL, DNS and the tunnel. If auth or its frontends are down, the
CLI, given database access, can still do every admin operation and repair
accounts: see [administration](../operations/administration.md). Recovering an
account whose owner lost every passkey follows
[account recovery](../security/account-recovery.md), including support's
evidence policy.
