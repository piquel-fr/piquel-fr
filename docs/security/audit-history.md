# Tamper-evident audit history

Auth records every account and security change as a domain event (see
[the database crate](../architecture/database-crate.md#domain-events)). Anyone
who can write to the database could otherwise edit, insert or delete events
without a trace. To prevent that, sealed events form a hash chain, and auth signs
checkpoints of the chain with a key the database never sees. Editing, inserting,
reordering or deleting a sealed event breaks the chain, and `auth-service audit
verify` names the first position that no longer matches.

The design follows piqueld's audit chain, with signed checkpoints added. It
borrows checkpoints from [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)
(Certificate Transparency 2.0), and uses
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON,
[C2SP signed notes](https://c2sp.org/signed-note) and
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032).

## How it works

### Sealing

Events are recorded unsealed, so a sign-in never waits on the chain. Every five
seconds, one replica's sealer job seals the events recorded since its last run,
under a PostgreSQL advisory lock. Sealing gives each event a position, from 1,
and a chain hash:

```text
chain_hash = SHA-256(previous chain_hash || SHA-256(canonical event))
```

The first event chains from 32 zero bytes, or, after pruning, from the anchor.
The canonical event is the RFC 8785 (JCS) form of the event's row: `position`,
`id`, `kind`, `version`, `occurred_at` (RFC 3339 in UTC, with microseconds),
`actor`, `subject`, `client`, `session`, `trace_id` and `payload`, as stored.

The sealer works in the order event consumers use, `(txid, sequence)`, and only
on events whose transaction, and every older one, has finished. No event can
therefore appear later before one already sealed. A long-running transaction
delays sealing for as long as it runs.

Auth runs as a restricted database role. It may insert events, but update only
their chain position and hash, which a trigger allows only while they are unset.
It may add checkpoints but not change them, and may not move the anchor. So a
compromise of auth alone cannot rewrite, delete or reorder sealed history. The
schema owner can, by dropping the triggers; the chain is what detects that.

### Personal data is not covered

IP addresses, browser families and every `Personal` payload value live in
`event_personal_data`, which the chain never hashes. The stored payload holds
`"$erased"` in their place. Retention, after 90 days, and account purges delete
those rows without touching the chain. The trade-off is that personal data is
not tamper-evident.

### Checkpoints

Every five minutes, if new events were sealed, the sealer signs a checkpoint of
the head in the C2SP signed-note format:

```text
auth.piquel.fr/audit
position 48211
head 3q2+7w…
time 2026-10-13T12:00:00Z

— auth.piquel.fr/audit <base64 key ID and Ed25519 signature>
```

`head` is the base64 chain hash at `position`. The note is stored in
`audit_checkpoints`, and checkpoints are never pruned.

### The audit key

Checkpoints are signed with a dedicated Ed25519 key. It is separate from the OIDC
signing key, so each can be rotated on its own. `AUTH_AUDIT_KEY_PROVIDER` is an
`env://` or `file://` reference to its 32-byte seed, written as 64 hex
characters. Auth ignores one trailing newline, and refuses to start with
anything else.

The key is named after the auth host, e.g. `auth.piquel.fr/audit`. Production
and staging each have their own, kept in piqueld's secret store as
`audit-key-production` and `audit-key-staging`, and their verifier keys are
committed to [`audit-key.pub`](audit-key.pub), one key per line. Every build
compiles that file in, so a compromised server cannot swap the key that `audit
verify` trusts. `audit verify` and `audit prune` trust only the key named after
`AUTH_PUBLIC_BASE_URL`'s host, so staging's key cannot vouch for production's
checkpoints. Previews get a fresh key that piqueld generates, the `audit-key`
secret, which is never committed. `auth-service keys audit` prints the verifier
key of the configured audit key.

### Publication

Checkpoints are public and cacheable for a minute. They hold only positions and
hashes:

- `GET /audit/checkpoints/latest`: the newest signed note, as `text/plain`.
- `GET /audit/checkpoints?after=<position>`: up to 100 checkpoints after a
  position, oldest first, as JSON `{position, hash, time, note}`.

Anyone can keep copies and later check that the history still extends them.

## Verifying

```console
$ auth-service audit verify
Chain: intact
Events checked: 1834
Checkpoints checked: 12
Unsealed: 0
Pruned through: 1203 9kD0…
Newest: 3037 b3Fx…
Latest checkpoint: 3000 q1Hc…
Keys: committed
```

Verification needs only the database, so it works from a bare recovery shell
(`just auth audit verify` locally). It reads one consistent snapshot, then:

1. Checks every checkpoint's signature against the committed keys, and that its
   note matches the position, head and time stored beside it.
2. Recomputes the chain from the anchor, and compares each event with its
   stored hash and each checkpoint with the recomputed head.
3. Fails if a sealed event remains at or before the anchor, which pruning would
   have deleted, or if a checkpoint is past the last sealed event.

It stops at the first position that does not match, prints why, and exits
non-zero. The change may also be a removal or insertion just before that
position.

| Problem | Meaning |
| --- | --- |
| `missing_event` | No sealed event has the position: one was deleted, or later events renumbered |
| `event_before_anchor` | A sealed event remains at or before the anchor: the anchor was moved to hide it |
| `event_changed` | The event's content or position does not match its stored hash |
| `checkpoint_mismatch` | The recomputed chain differs from the signed checkpoint: an earlier event changed and the stored hashes were recomputed to hide it |
| `checkpoint_signature` | No committed key signed the checkpoint |
| `checkpoint_malformed` | The note does not match the position, head or time stored beside it |
| `checkpoint_beyond_chain` | A checkpoint was signed past the last sealed event: newer events were deleted |

`--key <file>` checks against other verifier keys instead, e.g. a preview's, which
each preview generates on its own:

```sh
auth-service keys audit > preview-key.pub
auth-service audit verify --key preview-key.pub
```

`--output json` prints the same result as JSON. Run from a trusted build, the
CLI is the authoritative check: a compromised server could answer anything.

The admin dashboard's Audit tab shows the same verification, through the same
`AdminService` operation. It checks against the environment's committed key, or,
on a preview, which commits none, against the server's own key, and says so.

To detect truncation, also compare the published checkpoints with copies kept
elsewhere; see [Limits](#limits).

## Pruning

Without pruning, history is kept indefinitely. To prune:

```sh
auth-service audit prune --through <checkpoint position>
```

This deletes every event up to that checkpoint, with their personal data, and
makes the checkpoint the anchor that the remaining chain extends. It refuses a
position where no checkpoint was signed, one at or before the current anchor,
and any chain that does not verify through that position. Checkpoints are kept,
so the pruned history stays signed, and the prune itself is recorded as an
`audit_history_pruned` event with the operator.

Auth's own role may not delete events, so pruning connects as the schema owner:
set `AUTH_DATABASE_OWNER_URL` and `AUTH_DATABASE_OWNER_PASSWORD`, as for
`migrate`. The dashboard therefore never prunes. Its Audit tab lists the
checkpoints after the anchor, says by the same rules whether the chain may be
pruned through each, and shows the command that would.

## Rotating the audit key

1. Generate a seed with `openssl rand -hex 32 > seed`, and store it under a new
   name, e.g. `piquelctl app secret piquel-fr set audit-key-production-2 --file
   seed --environments production --no-previews`.
2. Print its verifier key with your local configuration, overriding the key and
   host: `AUTH_AUDIT_KEY_PROVIDER=file://$PWD/seed
   AUTH_PUBLIC_BASE_URL=https://auth.piquel.fr just auth keys audit`.
   Then delete `seed`.
3. In one change, add that line to `audit-key.pub`, keeping the old key, and
   point the environment's `audit_key` variable in `infra/piqueld.toml` at the
   new secret. Checkpoints signed by either key then verify.

Removing a key from the file makes the checkpoints it signed fail verification,
so keep every key that signed a checkpoint still in the database.

## Limits

- **Rewriting.** Someone with the schema owner's rights and the audit key can rewrite
  history and sign it again. Only checkpoint copies kept outside the server
  reveal this.
- **Truncation.** Someone with the schema owner's rights can delete the newest
  events along with the checkpoints that cover them. The remaining chain still
  verifies. Only a checkpoint copy kept elsewhere shows the deletion. Events newer
  than the last copy can disappear without a trace.
- **Recent edits.** Events are covered by a signature only once a checkpoint
  signs them: up to five minutes after they are sealed. Until then, someone with
  the schema owner's rights can edit them and recompute their hashes, and the
  next checkpoint signs the edited history. Before signing, the sealer
  recomputes the events since the latest checkpoint, so edits that leave the
  stored hashes as they were, and recent deletions, are refused instead.
- **New events.** Someone with auth's database role can insert events, which
  are then sealed and signed like genuine ones.
- **Pruning look-alikes.** Someone with the schema owner's rights can delete
  history up to a checkpoint and move the anchor, which looks like a prune
  without its `audit_history_pruned` event. Compare the anchor with the
  recorded prunes.
- **Retired keys.** Every key of an environment in `audit-key.pub` verifies its
  new checkpoints too. Remove a key that may be compromised, accepting that the
  checkpoints it signed then fail verification.
- **Personal data.** It is not covered by the chain (see above).
- **Unsealed events.** Events are covered only once sealed: within seconds,
  unless a long-running transaction holds sealing back.

### External witness: not implemented yet

The design calls for sending every checkpoint, through the
[delivery queue](../architecture/delivery-queue.md), to an append-only log that
neither an attacker nor the operator can rewrite, with `audit verify --witness`
comparing against it. That would turn truncation detection from "if someone kept
a copy" into "always, beyond the publication delay". It is deferred to a later
change. Sigstore's Rekor was the candidate, but Rekor v2 has no search and
does not accept the Ed25519 audit key, and Rekor v1 is in maintenance mode, with
a deprecated, best-effort search. Until a witness exists, keep copies of
`/audit/checkpoints/latest` somewhere the server cannot change, such as a
scheduled job's log, and compare them with `audit verify` from time to time.
