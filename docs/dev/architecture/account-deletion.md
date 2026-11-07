# Data export and account deletion

Owners download their data and delete their account on
`auth.piquel.fr/settings/data`. Both need a passkey confirmation from the last five
minutes, checked under the account lock, so no administrator can do either for
them, and neither can a session that never confirms, such as a recovery's
probation sign-in.

- **Download** sends one versioned JSON file (`"format": "piquel.account-export"`):
  profile, the handles it holds or held, email addresses, passkeys (label, dates
  and backup state, no key material), linked identities, devices with their IP
  addresses, an administrator's dashboard sign-ins, consents, refresh grants, the
  apps the account registered, its recoveries (dates, state and the passkey each
  enrolled, never a link), the security history, the notifications with when
  each was read, and which categories of them are emailed. It is read
  from one snapshot, holds no secret or digest, nothing may cache it, and it is
  recorded in the history.
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
  handles table without an owner, so no account claims them until an operator
  releases them (`handle release`). A purge that fails is retried after 5
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
