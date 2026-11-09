# Adding a notification

This guide adds a kind of notification: something SourceOrigin tells an account's
owner about their account, or administrators about the service, in their inbox
and by email. [Notifications](../architecture/notifications.md)
describes what the owner sees; [domain events](../architecture/database.md#notifications)
how notifications are stored.

A notification comes from an event: when an event about an account is
recorded, `DomainEvent::notification` decides whether it tells the account's
owner, and the event's transaction writes the notification and queues its
emails. So adding one changes no page, route or job.

## What you'll have at the end

- A `Notification` kind, written to the inbox in the transaction of the event it
  comes from.
- Its subject and body, which the inbox, the notification's page and its email
  all show.
- Its email, sent to the addresses you chose.

## Before you start

- Find the event the notification comes from. If the change records none yet,
  add one first: see [recording its event](admin-operation.md#3-record-its-event).
- Decide who is told. Every notification is emailed, and none can be turned off,
  so notify only what the owner needs to know about their account. A change the
  owner made themselves usually tells them nothing new.

## 1. Add the kind

Add a variant to `Notification` in `crates/common/src/notifications/mod.rs`:

```rust
/// Support removed the account's profile picture.
PictureRemoved,
```

A notification is stored as it serializes, under its snake_case `kind`, such as
`picture_removed`, so never rename one once released. It holds only enums, flags
and timestamps, never an address, a secret or a `Personal` value: it must read
the same once its event's personal data is erased. An older release skips a kind
it doesn't know, so adding one is safe during a deploy.

## 2. Map the event to it

In `DomainEvent::notification`, in the same file, move the event out of the
`return None` list into an arm of its own. The method names every event, so a new
event cannot be added without deciding:

```rust
Self::PictureRemoved {} if by_support => Notification::PictureRemoved,
```

`by_support` is true when an administrator or an operator at the CLI acted. Guard
on it when only support's change is news to the owner, and keep the owner's own
case in the `return None` list, with a comment saying why.

## 3. Choose who receives it

Add its arm to `Notification::audience`, which says whose inbox it goes to:

| `Audience` | Whose inbox |
| --- | --- |
| `Subject` | the account the event is about |
| `Administrators` | every active administrator, for an event about the service rather than one account, as a raised alert is |

Then add its arm to `Notification::addressees`, which says which of each
account's addresses receive its email:

| `Addressees` | Who receives the email |
| --- | --- |
| `Primary` | the primary verified address. An account without one gets no email |
| `Affected` | the address the event replaced or removed, so whoever reads that mailbox hears of it |
| `Verified` | every verified address, so one compromised mailbox cannot hide it |

Most notifications go to `Primary`. `Affected` reaches an address only for
the events whose address the `email` channel reads, in the `affected` match of
`crates/database/src/repositories/deliveries/email.rs`: name yours there too.
Use `Verified` for what an attacker holding one mailbox would want to hide, as a
recovery's notifications do.

A notification about the account itself is always emailed, and no preference
can turn it off. Only a kind that isn't about the account, as an announcement
isn't, may belong to an `EmailCategory` (`crates/common/src/notifications`),
whose email the owner turns off in their inbox's **Email preferences**. Only
announcements are wired today. A new category needs more than its variant, with
its `label` and `description`, which settings and the dashboard show:

- a migration widening the `CHECK` on `notification_preferences.category`
  (`0039_notification_preferences.sql`), or saving the preference fails;
- a check in the channel that sends its email, when the email is queued and
  when it is sent, as the `announcements_emailed` SQL function does for the
  `announcement` channel: the `email` channel checks no preference;
- a decision about its unsubscribe link, which `AccountService::unsubscribe`
  (`apps/auth-service/src/notifications/preferences.rs`) only handles for
  announcements.

See [email preferences](../architecture/notifications.md#email-preferences).

## 4. Write its texts

Add its arms to `Notification::subject`, one line, which is the inbox's line and
the email's subject, and `Notification::body`, what it says below:

```rust
Self::PictureRemoved => "SourceOrigin support removed your profile picture",
```

Write them for the owner: what happened to their account, what changes for them,
and what to do if they didn't expect it. The body may use the notification's own
fields, as `DeletionScheduled` formats its date. The email templates in
`apps/auth-service/templates/email/` render the subject and body as they are, so
they need no change.

## Test it

1. In `crates/common/src/notifications/tests.rs`, test which events notify and
   for whom, such as `only_support_renames_notify`, and the kind's stored form
   when it has fields, as `notifications_serialize_by_kind` does.
2. If the email goes to `Affected` or `Verified` addresses, add the kind to
   `notifications_are_emailed_to_the_addresses_their_kind_names`, in
   `apps/auth-service/src/deliveries/email/tests.rs`, which checks that each
   address receives it once.

```console
just test -p sourceorigin-common notifications
just db test -E 'test(notifications_are_emailed)'
```

## Document it

1. Add it to the list in [notifications](../architecture/notifications.md),
   which says what the inbox holds and who receives each email.
2. If the user guide describes the change that causes it, say there that the
   owner is told.

The inbox, the dashboard's notifications page, `auth-service account <user>
notifications`, the data export and the email all show every kind, so no other
surface needs a change.

## Limits

- **Links.** A notification's email links its page in the inbox. Only two
  kinds link to something else: a recovery's notifications link the recovery's
  undo page, through the `recovery_id` the `email` channel finds for them and
  the notification page's `about_recovery`, and an alert's links the
  dashboard's Alerts tab, through `Notification::links_alerts`. A new kind of
  link needs its email and its page both.
- **During a deploy.** The previous release's email workers may claim the email
  of a kind they don't know. They can't decode it, so they mark the delivery
  failed. An operator retries it with `auth-service deliveries retry <id>` once
  the new release serves; see [the delivery queue](../architecture/delivery-queue.md#operations).
