# Data export and account deletion

Owners download their data and delete their account on
`auth.piquel.fr/settings/data`. Both need a passkey confirmation from the last five
minutes, checked under the account lock, so no administrator can do either for
them, and neither can a session that never confirms, such as a recovery's
probation sign-in.

- **Download** sends one versioned JSON file (`"format": "piquel.account-export"`,
  version 3): profile, picture, the handles it holds or held, administrator
  rights and dashboard sign-ins, email addresses, passkeys (label, dates and
  backup state, no key material), linked identities, sessions with their devices,
  IP addresses and the apps each signed in to, consents, refresh grants, the apps
  the account registered with their related origins, its recoveries (dates, state
  and the passkey each enrolled, never a link), its notifications with when each
  was read, and last, every event about the account as stored (`kind` and
  `data`), with who acted, the app, and the request's IP address and device while
  they are kept. Passkeys, identities, sessions and grants that ended are in it
  until cleanup deletes them. Administrators' views of the account are left out,
  as its history leaves them out: a read may be a confidential inquiry. It holds
  no secret or digest, nothing may cache it, and it is recorded in the history.
- **The download streams.** The request reads every section but the events from
  one snapshot. A task then writes them, and the events 500 at a time, as the
  browser downloads, through a channel a few chunks deep, so a slow download
  holds the writer back rather than filling memory. The task keeps the snapshot,
  and its database connection, until the download ends, for at most 5 minutes.
  A replica therefore streams at most 2 exports at once, and refuses another
  with `429` until one ends. A failure partway, or the deadline, is logged and
  fails the download rather than saving a truncated file.
- **Deleting** asks for the account's handle. The account becomes `deleting`, every
  session and refresh grant ends, their apps receive back-channel logout tokens, and
  it can no longer sign in or authorize. For 30 days, signing in with one of its
  passkeys asks to restore it instead of signing in: the offer, valid for five
  minutes and used once, lives in its own cookie, and restoring signs in with that
  passkey, as its sign-in would have: a recovery's passkey in probation confirms
  nothing.
- **Purge:** every five minutes, one replica purges the accounts past their grace
  period. It deletes the apps the account registered, leaving tombstones with
  only their ID, settings and dates, then the account with its emails, passkeys,
  identities, sessions, grants, consents, email and announcement deliveries, and
  the announcements to chosen accounts it was the last recipient of, which may
  concern it, and the personal
  data (IP, device, provider subjects, app origins, operators' reasons) of every
  event it is the subject or actor of, including one a request records while the
  purge runs. The events stay, with pseudonymous IDs only. Its handles stay in the
  handles table without an owner, released at the purge: no account claims them
  for a year, when cleanup deletes them, unless an operator releases one sooner
  (`handle release`). A purge that fails is retried after 5
  minutes, then twice as long after each further failure, up to a day, behind
  the other due accounts. The account's admin page and `user show` give its
  failures and last error, and `piquel.auth.account_purge.failing` counts the
  accounts that failed 3 times in a row.

Administrators schedule and restore deletions from the account's page on the
admin dashboard, with a reason the owner sees in their history. Operators do the
same with the CLI, which alone also purges at once, in any status, since that
cannot be undone:

```sh
just auth user delete alice --reason "Asked by email"         # 30 days of grace
just auth user restore alice --reason "Changed their mind"
just auth user delete mallory --immediately --reason "Spam"   # cannot be undone
```

Nobody can delete the last active administrator's account. The account is told
of its scheduled deletion and of its restoration, as every
[notification](notifications.md) is. Applications are not yet told to erase their
records: that comes with
[#66](https://github.com/piquel-fr/piquel-fr/issues/66) and
[#97](https://github.com/piquel-fr/piquel-fr/issues/97).

## What auth stores, and for how long

`Table` (`crates/database/src/inventory/mod.rs`) names every table and what it
holds about the person behind an account: nothing, records the export includes
under a named section, or personal data it leaves out and why, such as digests
of secrets or sign-ins in progress. Tests hold the export and the purge to it:

- a database test fails while the schema has a table `Table` doesn't name, or
  a table with a foreign key to `users` that it says holds nothing;
- the export test seeds every table the export reads, and fails while the
  download lacks a section `Table` names;
- the purge test fails while a table with a foreign key to `users` holds no row
  of its account before the purge, or any row after it.

A new table therefore needs a decision before its tests pass.

Records an account no longer uses go on their own, in the cleanup pass every
five minutes (`MaintenanceRepository::purge_expired_auth_state`):

| Record | Deleted |
| --- | --- |
| Personal data of events: IP, device, reasons, `Personal` values | 90 days after the event |
| Revoked passkeys, unlinked identities | 90 days after they end |
| Recoveries | 90 days after they are undone, cancelled or settle, or their unused link expires |
| Ended sessions, with their IP addresses | a day after they end, or once no refresh grant or code needs them: about 31 days at most |
| Notifications | a year after they arrive |
| A purged account's handles | a year after the purge |
| Deliveries | 7 days after they succeed, 30 after they fail or are cancelled |

The 90 days match the events' personal data, so a history entry that still
shows its IP address still finds its passkey. The events themselves stay, with
pseudonymous IDs only: the audit chain covers them, and only pruning the audited
history removes them (see [Audit chain](database.md#audit-chain)). Everything
else lives as long as the account. Database backups keep what cleanup and
purges delete until they are replaced; piqueld manages them.
