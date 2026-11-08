# Administration

Administrators manage accounts, invitations, handles and auth's own state from
the admin dashboard, and operators from the `auth-service` command line. Both
run the same code.

## The command line

[auth-service commands](cli-commands.md) lists every command with its options.
Every administrative operation has a command, which runs the same code as the
admin dashboard (`AdminService` in `apps/auth-service/src/admin`), and so does every
setting administrators may change on another account (`AccountService` in
`apps/auth-service/src/account`). Commands need only `AUTH_DATABASE_URL`, so they
work while auth is down: they are the break-glass path when the dashboard or
auth's frontends are unreachable. `invite create` also needs
`AUTH_PUBLIC_BASE_URL`, to build its link; `user recover` needs it and
`AUTH_TOKEN_DIGEST_KEY`, to derive its link; `client origin add` needs it to tell
auth's own domain apart; and `audit verify` and `audit prune` need it to pick the
environment's audit key. `audit prune` connects as the schema owner (see
[audit history](../security/audit-history.md#pruning)). In deployed
environments, run them with `piquelctl app exec piquel-fr auth --env ENV --
auth-service …` (see [deploying](deploying.md#running-auth-service-commands)).

```sh
just auth admin grant alice               # the first administrator is granted here
just auth admin list
just auth admin revoke bob                # the last administrator's rights stay
just auth user search ali                 # by ID, or part of a handle, name or email
just auth user show alice                 # recorded, since it shows personal data
just auth user disable alice --reason "Spam"
just auth user enable alice
just auth user recover alice --reason "Lost every passkey"
just auth user recover alice --reason "Phone stolen" --revoke --keep <passkey-id>
just auth user undo-recovery alice --reason "Owner confirmed by phone"
just auth user delete alice --reason "Asked by email"   # see Data export and account deletion
just auth user restore alice --reason "Changed their mind"
just auth session revoke <session-id>     # one session, as `user show` lists it
just auth session revoke-all alice        # every session of the account
just auth audit list --user alice --kind session_revoked
just auth audit list --user alice --views # with administrators' views of the account
just auth audit verify                    # recompute the tamper-evident chain, and record what it found
just auth account alice passkeys list     # the account's settings, as its owner sees them
just auth account alice name set "Alice B" --reason "Asked by email"
just auth account alice passkeys revoke <passkey-id> --reason "Phone stolen"
just auth account alice emails remove <email-id> --reason "Asked by email"
just auth account alice apps remove <client-id> --reason "Impersonating app"
just auth account alice picture remove --reason "Impersonates someone"
```

- Accounts are named by handle, ID or a verified email of an active account.
- `--output json` prints the views the dashboard shows for `user search`
  (`UserPage`), `user show` (`UserDetail`), `audit list` (`EventPage`), `client
  list`, `invite list`, `admin list`, `announcement list` and `announcement show`
  (`AnnouncementDetail`), as defined in `piquel_common::admin`.
  `audit verify --output json` prints the verification.
- `audit verify` and `audit prune` are described in
  [audit history](../security/audit-history.md). `audit prune` connects as
  the schema owner when `AUTH_DATABASE_OWNER_URL` is set, since auth's own role
  may not delete events.
- `user disable|delete`, `user recover`, `user undo-recovery`, `session revoke-all`,
  `admin revoke`, `client disable|suspend|delete`, `audit prune`, `announcement
  send`, and `account …
  passkeys revoke`, `identities unlink` and
  `sessions revoke-all` describe what they will change and ask for confirmation.
  Without a terminal they refuse unless given `--yes`.
- `account <user>` reads and changes the settings administrators share with the
  owner: the display name, passkeys, social identities, email addresses,
  sessions, connected apps, the profile picture, the security history and the
  notifications, with the owner's own operations. It never adds a way to sign in
  or an address. Every change needs `--reason`, which the owner sees in their
  history; reads are recorded as views, once an hour per operator, which only the
  audit shows, not the owner. See
  [surfaces](../architecture/surfaces.md#changing-an-account-on-its-owners-behalf)
  for what is shared.
- `user recover` is for an owner who lost every passkey. It signs the account
  out everywhere, removes its unverified addresses, and emails its primary
  verified address a link to auth's `/recover`, which enrolls one passkey, once,
  within a day; it prints the link too, for an owner without an address. For 15
  days after, that passkey signs in but confirms no change, and any other passkey
  of the account can undo the recovery, which takes back its passkey, every
  session and every app consent. Until then, nobody removes a passkey but the
  recovery's own.
  - It first lists the account's recoveries of the last 15 days. While one is in
    probation, it refuses: find out who used it, and undo it with `user
    undo-recovery` first. An unused link is just replaced.
  - `--revoke [--keep <passkey-id>…]` is for an account that was in someone
    else's hands: it also revokes every passkey not kept, unlinks every social
    identity and withdraws every consent, and only prints the link. Remove the
    addresses the owner doesn't recognize afterwards, before handing the link
    over.
  - `user undo-recovery` undoes the account's recovery for an owner with no other
    passkey, or whose account is disabled, once support has confirmed them.
  - Before running either, follow the evidence policy in
    [account recovery](../security/account-recovery.md#supports-evidence-policy).
    Every reason shows in the account's history: write what was asked, never the
    evidence.
  - It never recovers an account while it holds administrator rights: revoke them
    with `admin revoke` first (grant another administrator first if it is the
    last). `admin grant` refuses while a recovery of the account can still be
    undone; grant the rights again once it settles.
- Each change is recorded as a domain event with the operator: `$USER` and the host
  name. Unlike the dashboard, the CLI may act on administrators' accounts, except
  to recover one.
- Failures print their causes and exit with 1; usage errors exit with 2.

## The admin dashboard

![The admin dashboard's overview: sign-in counts, recent events and the newest accounts](../../images/admin/overview.png)

Administrators manage accounts, their settings and security history, sessions,
invitations, other administrators, handles, announcements, the delivery queue,
signing keys and the origins approved for clients' pages to sign users in from
the admin dashboard,
which auth serves on `AUTH_ADMIN_LISTENER` for the dashboard's origin,
`AUTH_ADMIN_ORIGIN`, and which only a private route reaches.
Its pages call `AdminService` in-process; there is no admin API.

An administrator signs in by a handoff from auth: the dashboard sends the browser
to auth's `/admin` page, which needs a session signed in with a passkey, of an
account that still holds administrator rights, asks for the passkey again, and
sends it back with a single-use code bound to that session and to the
dashboard's state cookie. The dashboard's session lasts while that auth session
does, at most 12 hours, and ends after 30 minutes without a request. Every
request checks the administrator's rights again, and revoking them ends their
dashboard sessions, so either takes effect at once.
Changes also need the dashboard's own passkey confirmation from the last five
minutes: signing in gives one, and the administrator gives the next in a dialog
on the page, or on auth's `/admin` page, for the dashboard only. See [surfaces](../architecture/surfaces.md#adminpiquelfr).

The dashboard never changes an administrator's account: revoke their rights first.
Administrators cannot grant or revoke their own rights, and nobody can revoke the last
administrator's. Every change is recorded as a domain event with its administrator
or CLI operator.

Auth serves the admin dashboard on its admin listener, port 8081, for the
environment's admin host (`AUTH_ADMIN_ORIGIN`). Only the private `admin` route
reaches that port, in every environment; auth's health check stays on 8080. The
dashboard signs administrators in by a handoff from auth's own passkey session,
so it needs no OIDC client or secret.

Only administrators can use it. Grant the first one with the CLI:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service admin grant USERNAME
```

An administrator's dashboard session lasts while their auth session does, for at
most 12 hours, and ends after 30 minutes without a request or when their rights
are revoked. It survives restarts and replicas: it is stored, as a digest, in
PostgreSQL. Their security history records each sign-in and sign-out, and their
devices list it under the session it rests on.

## Invitations

```sh
just auth invite create --expires-in 7d
just auth invite list
just auth invite revoke <id>
```

`create` prints one signup link, to `/register` with the invitation filled in. A
signup through GitHub or Google asks for the invitation on its own page. The
database stores a digest, expiry and redemption time. Tokens expire after seven days by default; `h` and `d` are supported. A token
is redeemed atomically with account creation, so a failed signup does not spend it.
Disabling invitation enforcement affects signup only; existing users keep access.
Administrators can also list, create and revoke invitations from the admin dashboard.

## Handles

```sh
just auth handle check                                  # accounts whose handle is reserved
just auth handle rename old-name new-name --reason "…"  # --allow-reserved to assign a reserved name
just auth handle released                               # handles no account holds, kept from others
just auth handle release old-name                       # let anyone claim a released handle again
just auth handle reserve jane --reason "For Jane, joining in May"
just auth handle reserved                               # reserved handles, then the built-in names
just auth handle unreserve jane
```

Operators rename without the 30-day cooldown of settings renames, but not to a
handle another account holds or held, or one that looks like it (see
[security properties](../security/properties.md)). A rename bumps the account's profile
version, so relying parties refresh `preferred_username`. `release` deletes a
handle no account holds anymore, the only way one returns to the pool, for cases
like a trademark dispute; to free a current handle, rename its account first.
Every change is recorded as a domain event with its operator; a rename also with
its reason, which the owner sees in their history.

`reserve` keeps a handle for someone: signup and the settings refuse it and its
look-alikes, as they do the built-in reserved names (`admin`, `support`, …),
until an operator gives it with `rename --allow-reserved` or `unreserve`s it. Its
reason says who or what it is kept for. An account already holding it keeps it,
and `handle check` lists it.

The dashboard's Handles page does all of this: it lists the reserved handles,
with the built-in names, the accounts holding one, and the released handles, and
reserves, unreserves and releases them. An account's Change handle page renames
it with a reason, and may allow a reserved handle as `--allow-reserved` does.

## Announcements

Administrators tell accounts what they must know, such as a security incident or
a change to the privacy policy, with an announcement: a subject and a plain text,
to every account or to up to 1,000 chosen ones. Each recipient gets it as a
notification in their inbox (see [Notifications](../architecture/notifications.md)),
and by email at their primary verified address if they have one. It is not for
support conversations, which happen elsewhere.

On the dashboard:

1. Open **Announcements** and select **New announcement**.
2. Write the **Subject** and **Text**. Choose **Everyone**, or **These accounts**:
   paste a list, one handle, verified email or account ID per line, or type into
   the search box and select **Find**, then **Add** beside each account. Finding
   and adding save nothing.
3. Select **Save draft** to check the email first, or **Send** to send it now.
   Saving a draft needs no passkey; sending asks for one. Sending can't be taken
   back.

A draft goes to nobody, and any administrator may change or discard it; its page
shows the email exactly as it will be sent, and how many recipients it reaches.
Sending sends only the revision that was saved or checked: a draft changed
meanwhile, by another administrator say, is refused, to be checked again. Once
sent, nothing, not even the database's own role, changes its text, and its page
says how many recipients read it. One to everyone goes to every account at that
moment, disabled ones and ones being deleted included, since Piquel still holds
their data. Sending records an `announcement_sent` event with who sent it and to
how many accounts.

From the command line:

```sh
just auth announcement draft --subject "Security incident on 2 November" \
    --body-file incident.txt --everyone          # or --to alice --to bob; prints the draft's ID
just auth announcement show <id>                 # its text, recipients, and once sent, its emails
just auth announcement edit <id> --subject "…" --body-file - --to alice
just auth announcement send <id> --revision <n>  # the revision `show` printed; asks first
just auth announcement discard <id>              # a draft only
just auth announcement list
```

Its emails go out on the `announcement` delivery channel, apart from the `email`
channel's verification and recovery links, so sending one to every account holds
none of them back (see
[the delivery queue](../architecture/delivery-queue.md#announcements)).

## Outbound deliveries

Messages for other systems, such as back-channel logout tokens, email and
announcements, wait in
a queue in the database until a worker sends them. Inspect and repair it with:

```sh
just auth deliveries list --status failed
just auth deliveries retry <id>
just auth deliveries cancel <id>
```

A failed delivery with an ordering key holds back the ones after it until it is
retried or cancelled. After 30 days, cleanup deletes it and cancels the ones
behind it. See [the delivery queue](../architecture/delivery-queue.md).
