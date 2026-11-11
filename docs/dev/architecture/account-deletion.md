# Data export and account deletion

This page explains how auth exports an account's data and deletes the account:
the states an account goes through, the code that moves it between them, and what
each step guarantees. Read it before changing `apps/auth-service/src/deletion`,
the purge job, or anything that stores data about an account, which the export
and the purge must then cover.

## Lifecycle

```text
          schedule (owner, administrator, operator)
 active ─────────────────────────────────────────▶ deleting ──30 days──▶ purged
   ▲                                                  │
   └──── restore (a passkey sign-in, or support) ─────┘
 any status ──── user delete --immediately (operator) ──────────────▶ purged
```

- **`deleting`** is an account status. Its `account_deletions` row holds when it
  was requested, when it may be purged (`purge_after`, 30 days later:
  `GRACE_PERIOD_DAYS`), a pending restore offer, and the purge's failures. A
  trigger deletes the row whenever the account leaves `deleting`, however it
  leaves.
- **Purged** means gone: the account row and every row that identifies its
  person. What stays is pseudonymous: events, without their personal data,
  handles, without an owner, for a year, and the tombstones of the clients it
  registered.

## The code

`Deletions` (`src/deletion/mod.rs`) holds every step, in the caller's
transaction, each recorded as made in one `EventContext`. Three callers use it:

| Caller | Runs |
| --- | --- |
| `AccountService` (`src/deletion`) | the owner's export, deletion and restore |
| `AdminService` (`src/admin/service/accounts.rs`) | scheduling, restoring and, from the CLI only, purging at once, each with a reason |
| `AccountPurge` (`src/jobs/mod.rs`) | the purge of accounts past their grace period |

Every caller first takes `Deletions::lock`: the administrator list's lock, then
the account's, the order grants take them in. It refuses the last active
administrator's account, so the instance always keeps one. An administrator may
not schedule another administrator's deletion; the CLI may.

## Scheduling

`Deletions::schedule`, in one transaction:

1. sets the status to `deleting` and inserts the `account_deletions` row;
2. cancels any recovery whose link was not used, as disabling does;
3. records `AccountDeletionScheduled`, which notifies the owner
   ([notifications](notifications.md));
4. ends every session and refresh grant (`Session::end_all`), which queues the
   back-channel logout tokens of their apps ([sessions](sessions.md#expiry-and-revocation)).

From then on, the account cannot sign in or authorize, since sessions and
sign-ins need an active account. The owner's own deletion
(`AccountService::delete_account`) needs a passkey confirmation from the last
five minutes, checked under the account lock, and the account's handle typed
again. Its response clears the session cookie.

## Restoring

A passkey sign-in to an account scheduled for deletion signs nothing in
(`passkey/login.rs`). `Deletions::offer_restore` stores the digest of a
single-use token, valid five minutes, with the passkey that signed in, and the
browser keeps the token in the `__Host-sourceorigin_restore` cookie. A recovery's
passkey in probation gets no offer.

`AccountService::restore` reads the offer again under the account lock, so it
restores at most once, sets the account back to `active`, records
`AccountRestored`, and signs the browser in with the offer's passkey, as its
sign-in would have. A stolen session cannot restore anything: only a passkey
sign-in in the last five minutes makes an offer. The account kept its verified
addresses while `deleting`, so restoring never collides with another account.

Administrators and operators restore with `AdminService::restore_user`, from the
account's dashboard page or `auth-service user restore`.

## Purging

The `account-purge` job runs every five minutes, on one replica at a time
(`LockKey::AccountPurge`). Each run reads up to 100 due accounts, in the order
they became due, and purges each in a transaction of its own. Under the lock, it
checks again that the account is still `deleting` and due, since it may have
been restored meanwhile.

`Deletions::purge`, in one transaction:

1. ends every session and refresh grant;
2. deletes every client the account registered, leaving a tombstone with only
   its ID, settings and dates, so the ID is never reused;
3. deletes the account with its emails, passkeys, identities, sessions, grants,
   consents, email and announcement deliveries, picture and notifications, and
   the announcements to chosen accounts it was the last recipient of, which may
   concern it, then erases the
   personal data of every event it is the subject or actor of
   (`DeletionRepository::purge`). Its handles lose their owner, which releases
   them: cleanup deletes them a year later, when anyone may claim them, unless
   an operator releases one sooner (`handle release`);
4. records `AccountPurged`, once the account is gone, so the purge's own
   request data is not stored.

The purge erases event personal data last, on purpose: a request that stored
some while the account existed holds a lock the account's deletion waits for, so
the erasure sees it too, and a later one finds the account gone and stores none.
[The PostgreSQL boundary](database.md) explains the locks and lists the rows.

A purge that fails is recorded on its `account_deletions` row and retried after
5 minutes, then twice as long after each failure, up to a day, so an account
that keeps failing never holds back the others. The account's dashboard page and
`user show` give its failures and last error, and the
`sourceorigin.auth.account_purge.failing` gauge counts the accounts that failed 3
times in a row. While any do, the purge raises the `purges_failing` alert (see
[respond to an alert](../operations/administration.md#respond-to-an-alert)).

`AdminService::purge_user` purges at once, in any status, from the CLI only
(`user delete --immediately`), since it cannot be undone.

## Export

`AccountService::export` builds the owner's download, one JSON document
(`AccountExport` in `src/deletion/export`, `"format": "sourceorigin.account-export"`,
versioned). It needs the owner's passkey confirmation from the last five minutes,
checked under the account lock, where `AccountExported` is recorded before
anything is read. The document is then read from one snapshot
(`Database::begin_snapshot`), so its parts agree with each other.

It holds every record auth keeps about the account, and no secret, digest or key
material: passkeys show their label, dates and backup state only. Only the owner
may download it, never an administrator, since it carries every IP address and
every event about the account out of auth. Like every response, it is never
cached. Version 6 holds:

- the profile, picture, handles, administrator rights, email addresses,
  consents and refresh grants;
- passkeys, linked identities and sessions, ended ones included until cleanup
  deletes them, each session with its IP addresses, the apps it signed in to and
  the admin dashboard sessions resting on it;
- the browsers the account knows ([known devices](sessions.md#known-devices));
- the apps the account registered, deleted ones as their tombstones, with their
  related origins;
- its recoveries (dates, state and the passkey each enrolled, never a link);
- the inbox as stored, with when each notification was read, a kind a newer
  release wrote included, which categories are emailed, and the announcements
  it received;
- last, every event about the account as stored (`kind` and `data`), with who
  acted, the app, and the request's IP address and device while they are kept,
  unless an administrator or operator acted: theirs stay with the admin views.
  Administrators' views of the account are left out, as its history leaves them
  out: a read may be a confidential inquiry.

The document streams. The request reads every section but the events from the
snapshot. A task then writes them, and the events 500 at a time, as the browser
downloads, through a channel a few chunks deep, so a slow download holds the
writer back rather than filling memory. The task keeps the snapshot, and its
database connection, until the download ends, for at most 5 minutes. A replica
therefore streams at most 2 exports at once, and refuses another with `429`
until one ends. A failure partway, or the deadline, is logged and fails the
download rather than saving a truncated file.

## What auth stores, and for how long

`Table` (`crates/database/src/inventory/mod.rs`) names every table and what it
holds about the person behind an account: nothing, records the export includes
at a path, such as `clients/*/related_origins`, or personal data it leaves out
and why, such as digests of secrets or sign-ins in progress. Tests hold the
export and the purge to it:

- a database test fails while the schema has a table `Table` doesn't name, or
  a table with a foreign key to `users` that it says holds nothing;
- the export test gives an account a row in every table the export reads, and
  fails while the download holds nothing at a path `Table` names;
- the purge test fails while a table with a foreign key to `users` holds no row
  of its account before the purge, or any row after it.

A new table therefore needs a decision before its tests pass.

Records an account no longer uses go on their own, in the cleanup pass every
five minutes (`MaintenanceRepository::purge_expired_auth_state`):

| Record | Deleted |
| --- | --- |
| Personal data of events: IP, device, reasons, `Personal` values | 90 days after the event |
| Revoked passkeys, unlinked identities | 90 days after they end |
| Recoveries | 90 days after they are undone or settle, or their unused link is cancelled or expires, whichever comes first |
| Ended sessions, with their IP addresses | a day after they end, or once no refresh grant or code needs them: about 31 days at most |
| Known devices, with their browser and platform | 400 days after they were last seen |
| Notifications | a year after they arrive |
| Who received an announcement | a year after it is sent; one to chosen accounts goes with its last recipient |
| A purged account's handles | a year after the purge |
| Deliveries | 7 days after they succeed, 30 after they fail or are cancelled |

The 90 days match the events' personal data, so a history entry that still
shows its IP address still finds its passkey. The events themselves stay, with
pseudonymous IDs only: the audit chain covers them, and only pruning the audited
history removes them (see [Audit chain](database.md#audit-chain)). Everything
else lives as long as the account. Database backups keep what cleanup and
purges delete until they are replaced; piqueld manages them.

## Limits

Apps are not told to erase their own records of a purged account: that comes
with [#66](https://github.com/sourceorigin-dev/sourceorigin/issues/66) and
[#97](https://github.com/sourceorigin-dev/sourceorigin/issues/97). They hear of the
deletion only through back-channel logout, when its sessions end.
