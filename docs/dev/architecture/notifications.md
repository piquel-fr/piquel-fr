# Notifications

This page explains how auth tells an account's owner what happened to their
account: where notifications come from, how they are stored and emailed, and who
reads and marks them. Read it before adding an event that should notify its
subject, or changing the inbox.

## Where notifications come from

A notification is never written on its own: it comes from a domain event.
`DomainEvent::notification(&actor)` (`crates/common/src/notifications`) decides
which events tell their subject something, and what. It names every variant
under `#[deny(clippy::wildcard_enum_match_arm)]`, so a new event does not compile
until someone decides whether its subject is told. Some depend on who acted: a
display name, handle or picture changed by the owner tells them nothing, but one
changed by an administrator or operator does.

`Notification` is a closed enum, serialized with a `kind` tag. A variant holds
only enums, flags and timestamps, never a secret, an address or a `Personal`
value, so a notification renders from itself alone. Today the variants are a
replaced primary address, a removed address, a recovery that secured the account,
enrolled a passkey or was undone, an account disabled, enabled, scheduled for
deletion or restored, and support changing the handle or display name or removing
the picture.

## Storage

`DatabaseTransaction::record` (`crates/database/src/transaction.rs`) writes the
event, then, when the event has a subject and a notification, writes the
notification to the subject's inbox, then fans the event out to the delivery
channels, all in the event's transaction. So a committed event has its
notification and its email, and a rolled-back one has neither.

Each notification is a row of `notifications` (`NotificationRepository`):

| Column | Holds |
| --- | --- |
| `id` | the notification's ID, which its page's path names |
| `user_id` | the account, whose purge deletes its notifications by cascade |
| `event_id` | the event it came from; no foreign key, so it outlives the event's pruning |
| `payload` | the serialized `Notification` |
| `created_at` | when it was written |
| `read_at` | when the owner read it, or none while unread |

An account purged while a request was in flight gets no notification.
[Notifications](database.md#notifications) in the PostgreSQL page covers the
ordering of pages and the indexes.

## Email

Every notification is also emailed, and none can be turned off. The `email`
channel (`crates/database/src/repositories/deliveries/email.rs`) receives the
notification `record` just wrote and queues one `EmailMessage::Notification` per
address `Notification::addressees` names, each once:

- `Verified`: every verified address, for `AccountSecured` and `Recovered`, so
  one compromised mailbox cannot hide a recovery. An undone recovery
  (`RecoveryUndone`) goes to the primary address, like the rest.
- `Affected`: the address the event replaced or removed, so whoever reads that
  mailbox hears of it.
- `Primary`: the primary verified address, for every other notification. An
  account without one gets no email.

The delivery copies the address and the notification when they are written, so
removing the address right after cannot cancel it. The email links the
notification's page, and, while a passkey can still undo a recovery, the undo
page. [The delivery queue](delivery-queue.md#email) describes how it is sent.

## Reading and marking

Reading and marking are split by who may do them:

- **Reads** are shared settings operations on `AccountService`
  (`apps/auth-service/src/notifications`), which take a `Viewer`: the owner, an
  administrator on the dashboard, or an operator with
  `auth-service account <user> notifications list|show`. Reading never marks
  anything, so an administrator's look does not change what the owner sees.
  A notification's own read also returns its event's security history entry,
  while the history keeps it.
- **Marking** read or unread is the owner's alone, and takes an `Owner`, so no
  administrator can call it. The routes are `NotificationApplication`'s:
  `POST /account/notifications/{id}/read`, `…/{id}/unread` and
  `/account/notifications/read` for all. `GET /account/notifications`, `…/{id}`
  and `…/unread` read without marking.

The settings page of one notification (`src/web/settings/notifications.rs`)
marks it read when opened with `GET` and a `Sec-Fetch-Site` of `same-origin` or
`none`, so a link from another site cannot dismiss a notification unseen; a
browser that sends no fetch metadata marks nothing.

The owner's data export includes the inbox, with when each was read
([account deletion](account-deletion.md)).

## Guarantees

- A notification commits with its event, or not at all.
- It holds no personal data, so it reads the same once its event's personal data
  is erased, or the event pruned.
- A kind a newer release wrote reads as unknown, and the inbox skips it, so a
  rollback never breaks the inbox. Never rename a released kind.

## Adding a notification

1. Add the variant to `Notification` (`crates/common/src/notifications`), with
   its `subject`, its `body` and its `addressees`. The inbox, the dashboard and
   the email all show the subject and the body, so none needs a view of its own.
2. Return it from `DomainEvent::notification` for the events that give it.
