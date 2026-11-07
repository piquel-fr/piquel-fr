# Adding a delivery channel

This guide adds a channel to the outbound delivery queue: a kind of message auth
sends to another system, such as an audit witness's checkpoints. The queue
already gives every channel its guarantees, retries, leases, ordering, metrics
and operations; a channel supplies what it stores and how it sends.
[The delivery queue](../architecture/delivery-queue.md) describes how the queue
works.

The examples follow the back-channel logout channel:
`crates/database/src/repositories/deliveries/backchannel.rs` and
`apps/auth-service/src/deliveries/backchannel.rs`.

## What you'll have at the end

- Deliveries created in the transaction of the events that cause them, so a
  committed change has all its messages and a rolled-back one has none.
- Workers on every replica that send them, with retries and backoff, until the
  channel's maximum age.
- The channel in `auth-service deliveries` and on the dashboard's Deliveries
  page, which list, retry and cancel any channel's deliveries, and in the
  delivery metrics, labelled by its name.

## Before you start

Decide:

- **What a send needs.** A delivery copies it when it is created, so a send
  never reads rows that may have changed or gone since.
- **Whether receivers need deliveries in order.** An ordered delivery that fails
  holds back every later one with its key, so order only what must be.
- **How a receiver recognizes a repeat.** Delivery is at least once, so every
  attempt of a delivery carries the same delivery ID.

## 1. Define what it stores

In `crates/database/src/repositories/deliveries/`, add a module with a type that
implements `Channel`:

```rust
/// Logout tokens for the clients of revoked sessions.
pub struct BackchannelLogout;

impl Channel for BackchannelLogout {
    const NAME: &'static str = "backchannel_logout";
    type Recipient = LogoutRecipient; // client_id, sub, sid
    type Payload = ();

    /// One unordered delivery per client of a revoked session with a
    /// back-channel logout URI.
    async fn deliveries(
        event: &DomainEvent,
        _: Option<UserId>,
        _: Option<&Notified>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let DomainEvent::SessionRevoked { session_id, .. } = event else {
            return Ok(Vec::new());
        };
        // Read the clients and their logout URIs through a repository method,
        // then make one `NewDelivery` per client.
    }
}
```

- `NAME` is stored in every row, so never rename a released channel.
- `Recipient` holds the facts copied about the recipient, and `Payload` the
  message, both stored as JSON. Never store a plaintext secret in either.
- `deliveries` receives the event, its subject, and the notification it just gave
  the subject, if any, which the `email` channel sends. It runs inside the
  event's transaction, so it sees the rows as the change left them.
- Each `NewDelivery` names its `destination`, an endpoint URL or an address,
  and its `ordering_key`: `None` for unordered deliveries, as both channels
  today have.

Declare the module in `deliveries/mod.rs`, and export the channel and its
recipient from the crate root, `crates/database/src/lib.rs`, beside
`BackchannelLogout`.

## 2. Register it

Add the channel to `Registered` in `deliveries/mod.rs`, a nested list that
`DatabaseTransaction::record` fans every event out to:

```rust
pub(crate) type Registered = (BackchannelLogout, (Email, (Witness, ())));
```

A delivery that no event causes, such as a witness's checkpoint, is inserted
with `tx.deliveries().insert(None, delivery)` instead, and its channel needs no
registration.

## 3. Send it

In `apps/auth-service/src/deliveries/`, add a type that implements `Sender`, with
`type Channel` set to the new channel:

- `MAX_AGE` bounds how long a delivery keeps being retried, counted from its
  creation or an operator's last retry.
- `send` builds the message from the delivery, with `delivery.id` as its
  identity, and fresh timestamps such as a token's `iat` and `exp`, and sends it
  over HTTP with `OutboundClient`, which reaches only public HTTPS addresses and
  follows no redirect.
- It returns `DeliveryError::Retryable` or `DeliveryError::Permanent`.
  `OutboundClient::send` already classifies statuses and transport failures.

## 4. Start its workers

In `Jobs::start` (`apps/auth-service/src/jobs/mod.rs`), start the channel's
workers and its backlog count on every replica:

```rust
jobs.deliveries(WitnessSender::new(/* … */), database);
```

## 5. Handle duplicates

Decide how a receiver recognizes a repeated delivery, such as the `jti` of a
logout token or the `Message-ID` of an email, both made from the delivery ID,
and document it with the channel.

## Test it

1. In the database crate, test that the right events create the right
   deliveries, with their facts copied.
2. In auth-service, test how `send` maps the receiver's answers to outcomes.

The queue itself is tested in `deliveries/tests.rs` of both crates, so a channel
tests only its own part.

```console
just db test -E 'test(deliveries)'
```

## Document it

Add the channel to [Channels](../architecture/delivery-queue.md#channels): what
causes its deliveries, what each copies, how it is sent, its `MAX_AGE` and how
receivers deduplicate. Operators manage it as they do every channel, so the
CLI, the dashboard and [administration](../operations/administration.md#repair-outbound-deliveries)
need no change.
