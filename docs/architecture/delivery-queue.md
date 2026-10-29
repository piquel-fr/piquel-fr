# Outbound delivery queue

Auth sends messages to other systems through a PostgreSQL queue: back-channel
logout tokens, Security Event Tokens, SCIM requests, email and audit witness
checkpoints. Request handlers never send them inline. A slow or unreachable
receiver must not slow a login, and a message must survive a restart.

The repository owns the queue (`crates/database/src/repositories/deliveries/`).
Auth-service owns sending: the workers, the retry policy and the HTTP client
(`apps/auth-service/src/deliveries/`). Operators use `auth-service deliveries`.

## Guarantees

- **Created with the event.** `DatabaseTransaction::record` writes the event and
  every delivery it causes in the same transaction as the change. A committed
  change has all its deliveries; a rolled-back one has none.
- **Self-contained.** A delivery copies everything a send needs when it is
  created: the destination, and facts about the recipient such as `client_id`,
  `sub` and `sid`. Purging an account, deleting its sessions or changing a client
  afterwards does not change or lose a pending delivery. Email is the exception,
  on purpose: see [Email](#email).
- **At least once, with possible duplicates.** A worker that stops after sending
  but before recording the outcome lets its lease expire, and another worker sends
  the delivery again. Every attempt carries the same delivery ID, which receivers
  use to deduplicate: it is the `jti` of logout tokens and SETs, and the source of
  an email's `Message-ID`.
- **Ordered per key.** Deliveries that share an ordering key are sent one at a
  time, in the order their transactions committed, whatever the replicas' clocks
  say. A failed one holds back the rest until an operator retries or cancels it,
  which is recorded as `delivery_retried` or `delivery_cancelled` (cancelling one
  can hold back a notice to a user), or for 30 days, after which cleanup abandons the key: the failure is deleted
  and the deliveries behind it are cancelled, never sent out of order. A
  cancelled one holds back the rest until its last attempt's lease expires. Deliveries
  without a key are unordered.
- **Never secret.** Payloads are stored as they are, so they never hold a
  plaintext secret. `last_error` holds a status code or an error kind, never a
  response body.

## Life of a delivery

1. `record` calls each registered channel's `Channel::deliveries`, which inserts
   rows with status `pending`. An ordered delivery takes the next ordinal of its
   key from `delivery_orderings`, which locks the key until commit.
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
   `cancelled` ones after 30. A failed ordered delivery is abandoned instead,
   in a cleanup transaction covering up to 1,000 keys. For each key, cleanup
   locks the failure and the key's ordering row, cancels every delivery waiting
   behind it, and deletes it. An operator
   retry or cancel waits for that transaction and then finds the failure gone,
   and a key whose next delivery is still being inserted is skipped.

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
- 5 seconds to connect, 10 in total. Only the first 64 KiB of a response body
  are read.

HTTP 408, 429 and 5xx, timeouts, connection and DNS failures are retryable. Other
statuses, refused destinations and redirects fail at once.

## Email

The `email` channel (`deliveries/email/` in auth-service, `deliveries/email.rs` in
the database crate) sends account holders transactional messages over SMTP. A
delivery stores the account's ID as its recipient and a typed `EmailMessage` as
its payload. A verification link stores only the address's ID: the sender reads
the address, and the account's handle the message names, when it sends, so a link
to an address removed, replaced or verified meanwhile is not sent, and the
delivery succeeds without a send. The notices that an address stopped being
primary, or was removed, copy the address instead, read in the event's
transaction, so removing the address right after cannot cancel them. A recovery's
link stores the recovery's ID and the primary address's, and is not sent once the
link was used, cancelled or expired, or the account was disabled. The notices that
a recovery enrolled a passkey, or that support revoked passkeys and started one,
go to every verified address, copying it. The copied addresses are the channel's
only personal data, deleted with the delivery. The `destination` column names the
account and the address's ID, for operators.

A link's token is never stored, not even in the payload: it is an HMAC of the
address's ID, or the recovery's, under a key derived from the token digest key.
Settings store a verification token's SHA-256 digest when the address is added,
and a recovery stores its own when it starts; the sender derives the token again.
During a change of token digest key, it rebuilds a recovery's link under
whichever configured key derives the stored digest, so a link sent after the
change still works; if no configured key does, the delivery fails.
Every attempt therefore sends the same content and link, with the `Message-ID`
`<delivery ID@sender's domain>`. If the connection breaks after the
relay accepted a message, the delivery is retried and the mail may arrive twice;
mail clients that deduplicate on `Message-ID` hide the copy.

A permanent (5xx) SMTP reply fails the delivery. Temporary (4xx) replies, a
rejected login (`530`, `534`, `535`), timeouts, and connection or TLS failures
retry, for up to 24 hours, as long as a link works: a login fails on the relay's
key, not the message, so sending resumes once the key is fixed. The error recorded is the reply code, never its text, which can quote
the recipient. Without `AUTH_SMTP_URL`, the workers still run and drop every
delivery, so none waits forever.

Templates live in `apps/auth-service/templates/email/` and are checked at
compile time: each `EmailMessage` becomes a `Content` variant, which both the
plain-text and the HTML template must match.

## Operations

```sh
auth-service deliveries list [--status failed] [--channel scim] [--limit 100]
auth-service deliveries retry <id>    # a failed, or cancelled unordered, delivery
auth-service deliveries cancel <id>   # a pending or failed delivery
```

`just auth deliveries …` runs them with the caller's configuration. Retrying a
delivery makes it due now and restarts its channel's `MAX_AGE`. Cancelling an
ordered delivery is final, since the deliveries after it may already be sent. Cancelling an attempt in progress
cannot stop it from reaching the receiver, but its outcome is discarded, and the
deliveries ordered after it wait for its lease to expire.

## Channels

- **`backchannel_logout`**: OIDC Back-Channel Logout 1.0 tokens. Every early end of
  a session goes through `DatabaseTransaction::revoke_sessions`, which records one
  `SessionRevoked` per session. Its fan-out creates one unordered delivery per
  client that received tokens from the session (`oidc_session_clients`, which a
  trigger fills whenever any release redeems a code) and registered a back-channel
  logout URI. The recipient copies the
  client ID, `sub` and `sid`. `BackchannelLogoutSender` signs a token per attempt,
  with `iat` the attempt's time and `exp` two minutes later, and posts it as the
  `logout_token` form field. `jti` is the delivery ID. `MAX_AGE` is one hour.
- **`email`**: messages to account holders, sent over SMTP; see [Email](#email).

## Adding a channel

The examples follow the back-channel logout channel
(`repositories/deliveries/backchannel.rs`, `apps/auth-service/src/deliveries/backchannel.rs`).

1. **Define what it stores**, in `crates/database/src/repositories/deliveries/`:
   a type implementing `Channel`. `NAME` is stored in every row, so never rename a
   released channel. `Recipient` holds the facts copied about the recipient, and
   `Payload` the message, both serialized as JSON.

   ```rust
   /// Back-channel logout tokens (OIDC Back-Channel Logout 1.0).
   pub struct BackchannelLogout;

   impl Channel for BackchannelLogout {
       const NAME: &'static str = "backchannel_logout";
       type Recipient = LogoutRecipient; // client_id, sub, sid
       type Payload = ();

       /// One delivery per client the revoked session signed in to.
       async fn deliveries(
           event: &DomainEvent,
           _: Option<UserId>,
           tx: &mut DatabaseTransaction<'_>,
       ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
           let DomainEvent::SessionRevoked { session_id, .. } = event else {
               return Ok(Vec::new());
           };
           // Read the clients and their logout URIs through a repository method.
           let clients = tx.oidc().logout_clients(*session_id).await?;
           // ...one `NewDelivery` per client.
       }
   }
   ```

   `deliveries` runs inside the event's transaction, so it sees the rows as the
   change left them. Copy everything a send needs; a send must not read rows that
   can change or disappear. Set `ordering_key` only if receivers need deliveries
   in order, like SCIM per client and user, since a failure blocks the key.

2. **Register it** by adding it to `Registered` in `deliveries/mod.rs`, a nested
   list: `pub(crate) type Registered = (BackchannelLogout, ());`.

3. **Send it**, in `apps/auth-service/src/deliveries/`: a type implementing
   `Sender` with `type Channel = BackchannelLogout`. `MAX_AGE` bounds how long it
   keeps retrying. `send` builds the message with `delivery.id` as its identity,
   fresh timestamps such as `iat` and `exp`, and sends it with `OutboundClient`.
   Return `DeliveryError::Retryable` or `Permanent`; `OutboundClient::send`
   already classifies statuses and transport failures.

4. **Start its workers** in `Jobs::start` with `jobs.deliveries(sender, database)`.

5. **Handle duplicates.** Decide how a receiver recognizes a repeated delivery,
   and document it with the channel.

6. **Test it**: that the right events create the right deliveries with their facts
   copied, and how `send` maps the receiver's answers. The queue itself is tested
   in `deliveries/tests.rs` of both crates.

A delivery that no event causes, like a witness checkpoint, is inserted with
`tx.deliveries().insert(None, delivery)` instead.
