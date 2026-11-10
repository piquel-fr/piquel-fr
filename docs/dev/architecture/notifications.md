# Notifications

This page explains how auth tells an account's owner what happened to their
account, and administrators what happened to the service: where notifications
come from, how they are stored and emailed, and who reads and marks them. Read
it before adding an event that should notify someone, or changing the inbox.

## Where notifications come from

A notification comes from a domain event, except an announcement: sending one
writes each recipient's notification directly, since no event about the account
does. A message to one account comes with its `MessageSent` event, but the event
holds no text, so `DatabaseTransaction::record_message` gives the account the
message itself, with the event. Every other notification comes from its event.
`DomainEvent::notification(&actor)` (`crates/common/src/notifications`) decides
which events tell someone something, and what. It names every variant under
`#[deny(clippy::wildcard_enum_match_arm)]`, so a new event does not compile until
someone decides whether anyone is told. `Notification::audience` says whose
inbox it goes to: the event's subject, or for a raised alert, which concerns the
service rather than one account, every active administrator. Some depend on who
acted: a display name, handle or picture changed by the owner tells them nothing,
but one changed by an administrator or operator does.

`Notification` is a closed enum, serialized with a `kind` tag. A variant holds
only IDs, enums, flags and timestamps, never a secret, an address or a `Personal`
value, so a notification renders from itself alone. There are three exceptions.
`Announcement` holds the subject and text administrators wrote. A targeted
announcement's text may name its recipients, so it goes with them: purging an
account deletes its notifications, and the announcement once its last
recipient is purged. `Message` holds the subject and text of
[a message to the account](../operations/administration.md#message-an-account),
which may be personal: it and its queued email hold the message's only copies,
so purging the account deletes both, and its `message_sent` event, which the audit chain keeps, records
only who sent it. `AlertRaised` holds the alert's subject and text, which
name no account, rather than the `Alert`, so an older release's inbox never
meets an alert it cannot decode. Today the variants are a replaced primary
address, a removed address, a recovery that secured the account, enrolled a
passkey or was undone, an account disabled, enabled, scheduled for deletion or restored,
support changing the handle or display name, renaming a passkey or removing the
picture,
[administrators' announcements](../operations/administration.md#send-an-announcement)
and messages, and, in administrators' inboxes, each
[alert](../operations/administration.md#respond-to-an-alert) when it is raised,
titled **Alert:** and the alert's subject. An alert's notification has no
security history entry, since its event concerns no account, and neither has a
message's: the inbox already shows it. The
[security alerts](#security-alerts) are the rest.

## Security alerts

Every notification but an announcement, a message and a raised alert is about
the account's security (`Notification::security`): it is always emailed, and
its email carries a [sign-out link](#the-sign-out-link). Besides the account
notices above, these events alert the owner:

| Event | Notification |
| --- | --- |
| `SignedIn { new_device: true }` (see [known devices](sessions.md#known-devices)) | `NewDeviceSignIn` |
| `PasskeyAdded`, `PasskeyRemoved` | `PasskeyAdded`, `PasskeyRemoved` |
| `IdentityLinked`, `IdentityUnlinked` | `IdentityLinked`, `IdentityUnlinked`, naming the provider |
| `EmailAdded` | `EmailAdded`, naming the provider an address imported on linking came from |
| `GrantRevoked { reason: RefreshReplay }` | `TokenReused` |
| `RecoveryStarted` without `--revoke` | `RecoveryStarted`, to every verified address, with the undo page |
| `SessionRevoked { reason: Admin }` | `SignedOutBySupport` |
| `CompromiseReported` | `CompromiseReported`, confirming the report |
| `SignInFailed { reason: CounterRegression }` | `PasskeyCopied` |
| `SignInFailed { reason: AccountUnavailable }` | `SignInRefused`: a credential was proven on a disabled account |

Two rules keep one operation from alerting several times:

- **An operation without a session tells the owner as a whole.** Signing up, a
  recovery's link and its undo page act as `Actor::User { session_id: None }`
  or `Actor::Anonymous`, and the passkeys, identities and addresses they add or
  remove alert no one: the account's creation needs no alert, and a recovery
  has its own notifications. Support's own steps of a recovery, the passkeys
  and identities `--revoke` and an undo take back, are recorded with
  `DatabaseTransaction::record_quietly`, which writes no notification.
- **A consequence is told once.** `SignedOutBySupport` is a
  `Notification::consequence`: `record` skips it for an account the
  transaction already notified. Support ending several sessions tells the owner
  once, and ending them while recovering the account tells them nothing more
  than the recovery's notification.

### The sign-out link

The email of every security notification carries
`/sign-out-everywhere?id=<notification>&token=<token>`, for an owner whose session
was stolen while their passkey is out of reach. The token is the HMAC of the
notification's ID under a key derived from the token digest key, like an
unsubscribe link's (`Links` in `src/notifications/links.rs`). Opening the link
shows a page asking first, so a mail scanner changes nothing, and only while the
link still works (`AccountService::sign_out_link_works`); otherwise it says the
link doesn't work, with a 404. Its form, posted from that page without a
session, runs `AccountService::sign_out_everywhere`: under the account lock, it
marks the notification's `signed_out_at`, records
`DomainEvent::SignedOutEverywhere`, even when no session is left, so the owner's
history shows every use, then ends every session and refresh grant with
`RevocationReason::SignOutLink`, as the owner without a session. It revokes no credential, so the worst a leaked link
can do is sign the owner out. The link works once, within seven days of the
notification (`SIGN_OUT_LINK_LIFETIME`).

### The top bar's bell

Every account page's top bar has a bell (`InboxLink` in `crates/ui/src/layout`)
linking the inbox, with the unread count the sidebar's Notifications tab shows.
The owner answers an alert from its page: opening it from auth's own pages marks
it read, and **This wasn’t me**, where the security history lets the owner
report the notification's event, reports it
(`HistoryChange::Report { notification }`). Read state lives on the
notification, so every device sees it.

## Storage

`DatabaseTransaction::record` (`crates/database/src/transaction.rs`) writes the
event, then, when the event gives a notification, writes it to the inbox of each
account of its audience, then fans the event out to the delivery channels, all
in the event's transaction. So a committed event has its notifications and
their emails, and a rolled-back one has neither. For a raised alert, it reads
the active administrators and key-share locks their rights and accounts until
the event commits, so a purge of one waits, then deletes its notification and
email with the account.

Each notification is a row of `notifications` (`NotificationRepository`):

| Column | Holds |
| --- | --- |
| `id` | the notification's ID, which its page's path names |
| `user_id` | the account, whose purge deletes its notifications by cascade |
| `event_id` | the event it came from; no foreign key, so it outlives the event's pruning |
| `payload` | the serialized `Notification` |
| `created_at` | when it was written |
| `read_at` | when the owner read it, or none while unread |
| `signed_out_at` | when its email's [sign-out link](#the-sign-out-link) was used |

An account purged while a request was in flight gets no notification. Cleanup
deletes a notification a year after it arrives, and an announcement's
recipients a year after it is sent: the dashboard then says whom it went to was
deleted, rather than counting none.
[Notifications](database.md#notifications) in the PostgreSQL page covers the
ordering of pages and the indexes.

## Email

Every notification is also emailed, except an announcement whose recipient
turned announcements' email off (see [email preferences](#email-preferences)).
Notifications about the account itself can't be turned off, and neither can an
alert's. The `email` channel
(`crates/database/src/repositories/deliveries/email.rs`) receives the
notifications `record` just wrote, each with its account, and queues one
`EmailMessage::Notification` per address of that account that
`Notification::addressees` names, each once:

- `Verified`: every verified address, for `AccountSecured`, `Recovered` and
  `RecoveryStarted`, so one compromised mailbox cannot hide a recovery. An undone recovery
  (`RecoveryUndone`) goes to the primary address, like the rest.
- `Affected`: the address the event replaced or removed, so whoever reads that
  mailbox hears of it.
- `Primary`: the primary verified address, for every other notification, an
  alert's and a message's included. An account without one gets no email.

An announcement's email goes out on the `announcement` channel instead, which
has workers of its own and links the inbox (see
[announcements](delivery-queue.md#announcements)). A message's email reads like
an announcement's: the text administrators wrote, in its paragraphs, then a line
linking the inbox, which lets the dashboard show the email exactly as it will be
sent. It carries no unsubscribe link.

The delivery copies the address and the notification when they are written, so
removing the address right after cannot cancel it. The email links the
notification's page, and, while a passkey can still undo a recovery, the undo
page. An alert's email, and its page in the inbox, link the dashboard's Alerts
tab while auth serves a dashboard (`Notification::links_alerts`).
[The delivery queue](delivery-queue.md#email) describes how it is sent.

## Email preferences

Notifications about the account itself are always emailed, so no switch can
hide one from its owner. The categories whose email the owner may turn off are
`EmailCategory`'s variants, today only `announcements`, on by default.
`notification_preferences` stores a row only once the owner chooses, and
`NotificationRepository::preferences` fills in the default for the others. An
announcement that is not essential is emailed only to recipients whose
Announcements email is on, both when its deliveries are queued and when each is
sent; an essential one goes to every recipient with a primary verified address
(see [the delivery queue](delivery-queue.md#announcements)).

The owner turns a category on or off in the inbox's **Email preferences**
dialog, which a change reopens, or with
`PUT /account/notifications/preferences` and a body such as
`{"category": "announcements", "email": false}`; their session is enough. A
change records `NotificationPreferenceChanged`, which the security history
shows, and a choice that changes nothing records nothing.
`GET /account/notifications/preferences` lists every category. Administrators
see them, read-only, on the account's Notifications page of the dashboard, and
operators with `account <user> notifications preferences`: an operator turning
email off could hide a notice from the owner. The data export includes them.

An announcement's email that is not essential carries an unsubscribe link,
`/unsubscribe?id=<account>&token=<token>`, in its body and in the
`List-Unsubscribe` header, with `List-Unsubscribe-Post: List-Unsubscribe=One-Click`
(RFC 8058), so mail clients offer it in one click. They do so only when the
relay's DKIM signature covers both headers, which the relay must be set up to
sign. The token is the HMAC of the account's ID under a key derived from the
token digest key, so it is stored nowhere and never expires; holding it only
turns that account's announcements' email off. Opening the link shows a page
asking first, so a mail scanner that follows links changes nothing. A `POST` to
it, from that page or a mail client, turns the email off as the owner without a
session, and the security layer accepts it from any origin: the link is its
credential.

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
[Notifications](../../user/account/notifications.md) is the owner's guide.

## Guarantees

- A notification commits with its event, or not at all.
- It holds no personal data, so it reads the same once its event's personal data
  is erased, or the event pruned.
- A kind a newer release wrote reads as unknown, and the inbox skips it, so a
  rollback never breaks the inbox. Never rename a released kind.

## Adding a notification

1. Add the variant to `Notification` (`crates/common/src/notifications`), with
   its `subject`, its `body`, its `audience` and its `addressees`. The inbox,
   the dashboard and
   the email all show the subject and the body, so none needs a view of its own.
2. Return it from `DomainEvent::notification` for the events that give it.
