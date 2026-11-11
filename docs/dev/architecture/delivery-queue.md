# Outbound delivery queue

This page explains how auth sends messages to other systems without slowing a
request: the queue's guarantees, the life of a delivery, its channels, and how
to add one.

Auth sends messages to other systems through a PostgreSQL queue. Four channels
exist: back-channel logout tokens, email, announcements and invitations (see
[Channels](#channels)). Other
kinds, such as audit witness checkpoints, would join them as channels of their
own. Request handlers never send them inline. A slow or unreachable
receiver must not slow a login, and a message must survive a restart.

The repository owns the queue (`crates/database/src/repositories/deliveries/`).
Auth-service owns sending: the workers, the retry policy and the HTTP client
(`apps/auth-service/src/deliveries/`). Operators list, retry and cancel
deliveries with `auth-service deliveries` or on the admin dashboard's Deliveries
page.

## Guarantees

- **Created with the event.** `DatabaseTransaction::record` writes the event and
  every delivery it causes in the same transaction as the change. A committed
  change has all its deliveries; a rolled-back one has none.
- **Self-contained.** A delivery copies everything a send needs when it is
  created: the destination, and facts about the recipient such as `client_id`,
  `sub` and `sid`. Purging an account, deleting its sessions or changing a client
  afterwards does not change or lose a pending delivery. Email and announcements
  are the exception, on purpose: see [Email](#email) and
  [Announcements](#announcements).
- **At least once, with possible duplicates.** A worker that stops after sending
  but before recording the outcome lets its lease expire, and another worker sends
  the delivery again. Every attempt carries the same delivery ID, which receivers
  use to deduplicate: it is the `jti` of logout tokens, and the source of an
  email's `Message-ID`. Auth-service's `deliveries/tests.rs` kills a replica
  mid-send, and stalls another past its lease, to check this end to end.
- **Unordered.** Each delivery is sent on its own, so a failed one never holds
  back another. Receivers must not rely on the order deliveries arrive in.
- **Never secret.** Payloads are stored as they are, so they never hold a
  plaintext secret. `last_error` holds a status code or an error kind, never a
  response body.

## Life of a delivery

1. `record` calls each registered channel's `Channel::deliveries`, which inserts
   rows with status `pending`.
2. Every replica runs two workers per channel. A worker claims the longest-due
   delivery with `FOR UPDATE SKIP LOCKED`, sets a fresh claim token and a 60 second
   lease, and commits. Idle workers poll every second.
3. It sends outside any transaction, with a 10 second timeout. A delivery that
   waited past its channel's `MAX_AGE`, counted from its creation or from an
   operator's last retry, fails without being sent.
4. It records the outcome only if its claim token still holds the delivery. If
   another worker claimed it after the lease expired, or an operator cancelled
   it, the outcome is discarded and logged as a lost lease.
   - Success: `succeeded`.
   - Retryable error: back to `pending`. The next attempt waits a random time up
     to a bound that starts at 10 seconds and doubles to an hour, or longer if
     the receiver's `Retry-After` asks. A shorter `Retry-After` never skips the
     backoff, so a receiver cannot make workers retry it constantly.
   - Permanent error, or a retry later than the channel's `MAX_AGE` after
     creation: `failed`.
5. The cleanup job deletes `succeeded` deliveries after 7 days and `failed` or
   `cancelled` ones after 30.

## Outbound HTTP

Destinations come from client registrations, which third parties can supply.
`OutboundClient` keeps them from reaching this network:

- HTTPS only.
- Redirects are refused, never followed. A 3xx fails the delivery.
- The host is resolved once, and refused if any address is in a range that is
  not globally reachable: loopback, private, link-local, unique-local, shared,
  local-use NAT64, multicast, reserved and the like. An IPv4-mapped, NAT64 or
  6to4 address is also checked as the IPv4 address it reaches. The connection
  goes to the checked addresses. IP literals get the same check, and proxies are
  never used, since a proxy would resolve the name itself.
- 5 seconds to connect, 10 in total.
- Only the status decides the outcome. It is taken as soon as the response's
  headers arrive, and the body is never read, so a receiver that accepts a
  delivery and then stalls cannot turn it into a retry. A profile picture is
  the one body fetched, up to its size limit.

HTTP 408, 429 and 5xx, timeouts, connection and DNS failures are retryable. Other
statuses, refused destinations and redirects fail at once.

## Email

The `email` channel (`deliveries/email/` in auth-service, `deliveries/email.rs` in
the database crate) sends account holders transactional messages over SMTP. A
delivery stores the account's ID as its recipient and a typed `EmailMessage` as
its payload. A verification link stores only the address's ID: the sender reads
the address, and the account's handle the message names, when it sends, so a link
to an address removed, replaced or verified meanwhile, or of an account no longer
active, is not sent, and the delivery succeeds without a send. A recovery's
link stores the recovery's ID and the primary address's, and is not sent once the
link was used, cancelled or expired, or the account was disabled.

Every notification an event gives (`DomainEvent::notification`) is emailed
too: `record` hands the notifications it just wrote, each with its account, to
the channels, and the `email` channel queues one `EmailMessage::Notification`
per address of that account that `Notification::addressees` names, each once.
A recovery that secured the account or added a passkey (`AccountSecured`,
`Recovered`) goes to every verified address, so a compromised one cannot hide
it; a replaced or removed address's to that address, so whoever reads it hears
of it; any other to the primary verified address, and an account without one
gets no email. The message copies the address and the notification, read in the
event's transaction, so removing the address right after cannot cancel it, and
says what the inbox says. It links the notification's page, except a message's,
which reads like an announcement's and links the inbox. A recovery's also
links its undo page while a passkey can still undo it, and an alert's links the
dashboard's Alerts tab while auth serves one. The copied addresses, and a
message's text, which may be personal, are the channel's only personal data,
deleted with the delivery. The `destination`
column names the account and the address's ID, for operators.

A link's token is never stored, not even in the payload: it is an HMAC of the
address's ID, or the recovery's, under a key derived from the token digest key.
Settings store a verification token's SHA-256 digest when the address is added,
and a recovery stores its own when it starts; the sender derives the token again.
During a change of token digest key, it rebuilds either link under whichever
configured key derives the stored digest, so a link sent after the change still
works; if no configured key does, the delivery fails.
Every attempt therefore sends the same content and link, with the `Message-ID`
`<delivery ID@sender's domain>`. If the connection breaks after the
relay accepted a message, the delivery is retried and the mail may arrive twice;
mail clients that deduplicate on `Message-ID` hide the copy.

A permanent (5xx) SMTP reply fails the delivery. Temporary (4xx) replies, a
rejected login (`530`, `534`, `535`), timeouts, and connection or TLS failures
retry, for up to 24 hours, as long as a link works: a login fails on the relay's
key, not the message, so sending resumes once the key is fixed. The error recorded is the reply code, never its text, which can quote
the recipient and is never logged either. Without `AUTH_SMTP_URL`, the workers still run and drop every
delivery, so none waits forever.

Each `EmailMessage`, and each announcement's email, becomes an `EmailContent`
(`crates/ui/src/email/content.rs`), which says what that kind of email says as
blocks: paragraphs, text kept as written, an action and small print. A `Mail`
renders the blocks twice, as the plain-text body and as the HTML body, styled
inline, so every sentence is written once and the two bodies always agree. Each
kind's subject and bodies are a snapshot in
`apps/auth-service/src/deliveries/email/snapshots/`, so a change to what an
email says shows in review.

## Announcements

The `announcement` channel (`deliveries/announcement.rs` in the database crate,
`AnnouncementSender` beside `EmailSender` in auth-service) emails the
announcements administrators send. It is a channel of its own, with workers of
its own, so an announcement to every account never holds back a verification or
recovery link on the `email` channel; it shares the relay, the email bodies and
the `Message-ID` scheme with it.

Sending an announcement writes a notification of kind `announcement`, with its
subject and text, to each recipient's inbox, from the recipients it locked, and
records `AnnouncementSent`, whose fan-out creates one delivery per
recipient with a primary verified address, leaving out, unless the announcement
is essential, those who turned announcements' email off
([email preferences](notifications.md#email-preferences)). These emails go out
here, never on the `email` channel, and link the inbox. Each names its list in
a `List-Id` header (RFC 2919), `<announcements.<sender's domain>>`, so mail
clients can sort and filter announcements, and one that is not essential also
carries the recipient's one-click unsubscribe link, in its body and its
`List-Unsubscribe` headers. The sender's `Stream` decides these headers for
every kind of email: bulk mail gets them, and transactional mail, every email
about the account itself, none. A delivery stores only the account's ID
as its recipient and the announcement's ID as its payload, and its `destination`
names both. The sender reads the account's primary verified address and the text
when it sends, so an address changed meanwhile gets it, and an account with none
left, no longer a recipient, or that turned announcements' email off since,
unless it is essential, is skipped: the delivery succeeds without a send. The text of a sent announcement never changes, so every attempt sends the
same message. `MAX_AGE` is three days, as an announcement stays worth reading
through a long relay outage or a slow send to every account. A purge deletes the
account's announcement deliveries, which would find no recipient left.

## Invitations

The `invitation` channel (`deliveries/invitation.rs` in the database crate,
`InvitationSender` beside `EmailSender` in auth-service) mails an invitation's
link to the address it invites, which belongs to no account yet, so it cannot
be the `email` channel's recipient. Creating a mailed invitation, or sending it
again, records `InvitationMailed`, whose fan-out creates one unordered delivery.
It stores only the invitation's ID, as its recipient and in its `destination`.
The sender reads the address and the token's digest when it sends, and derives
the link's token again from the ID, as a recovery link's is, so the token is
stored nowhere. An invitation redeemed, revoked or expired meanwhile is skipped:
the delivery succeeds without a send. `MAX_AGE` is three days.

## Operations

```sh
auth-service deliveries list [--status failed] [--channel email] [--limit 100]
auth-service deliveries retry <id> --reason "…"    # a failed or cancelled delivery
auth-service deliveries cancel <id> --reason "…"   # a pending or failed delivery
```

`just auth deliveries …` runs them with the caller's configuration, and each
change is recorded as `delivery_retried` or `delivery_cancelled`. Retrying a
delivery makes it due now and restarts its channel's `MAX_AGE`. Cancelling an
attempt in progress cannot stop it from reaching the receiver, but its outcome
is discarded.

### Metrics

Labelled by `channel`, and the attempt counter also by a closed `outcome`, never
by destination, client or user. The Auth
overview dashboard charts them in its Deliveries row.

| Metric | Kind | Meaning |
| --- | --- | --- |
| `sourceorigin.auth.deliveries.attempts{channel, outcome}` | Counter | Attempts by outcome, counted where the worker records it: `succeeded`, `retried`, `failed`, or `lease_lost` when its claim token no longer held the delivery and the outcome was discarded |
| `sourceorigin.auth.deliveries.pending{channel}` | Gauge | Deliveries waiting for an attempt, or being attempted |
| `sourceorigin.auth.deliveries.oldest_pending_age{channel}` | Gauge, seconds | Time since the oldest pending delivery was created, or last retried by an operator |

An attempt whose outcome could not be recorded, because the database failed, is
logged and not counted; its lease expires and it is attempted again. Every
replica counts each channel's pending deliveries every 30 seconds, through
`deliveries_due_idx`, and reports the same queue-wide numbers, so dashboards
take their maximum rather than their sum. A failed count drops the channel's
gauges until the next one succeeds.

## Channels

- **`backchannel_logout`**: OIDC Back-Channel Logout 1.0 tokens. Every early end of
  a session goes through `DatabaseTransaction::revoke_sessions`, which records one
  `SessionRevoked` per session. Its fan-out creates one delivery per
  client that received tokens from the session (`oidc_session_clients`, which a
  trigger fills whenever any release redeems a code) and registered a back-channel
  logout URI. The recipient copies the
  client ID, `sub` and `sid`. `BackchannelLogoutSender` signs a token per attempt,
  with `iat` the attempt's time and `exp` two minutes later, and posts it as the
  `logout_token` form field. `jti` is the delivery ID. `MAX_AGE` is one hour.
- **`email`**: messages to account holders, sent over SMTP; see [Email](#email).
- **`announcement`**: announcements' emails to their recipients, sent over SMTP;
  see [Announcements](#announcements).
- **`invitation`**: invitations' links, mailed to the addresses they invite, sent
  over SMTP; see [Invitations](#invitations).

To add a channel, see [adding a delivery channel](../extending/delivery-channel.md).
