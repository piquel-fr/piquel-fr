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

Each sealed event records the format of its canonical event in `chain_format`,
so a later format can add a field without breaking the hashes of events sealed
before it. Format 1, the original, has no `format` field. Format 2 adds only
`"format": 2`, and every later format names itself the same way. This release
verifies both and still seals format 1, which the release before it verifies
too; the next release seals format 2. Verification refuses a format it does not
know, rather than report the chain broken.

The sealer works in the order event consumers use, `(txid, sequence)`, and only
on events whose transaction, and every older one, has finished. No event can
therefore appear later before one already sealed. A long-running transaction
delays sealing for as long as it runs. Histories list events in the same order,
newest first, so sealed history is listed in chain order: the chain does not
cover `txid` and `sequence`, but verification checks that they agree with it.

Auth runs as a restricted database role. It may insert events, but not choose
their transaction, time, sequence or chain columns, which keep their defaults,
nor store one auth could not read back, such as one over 8 KiB, which would stop
every sealing pass. It may update only their chain position, hash and format,
which triggers allow only while they are unset, and only at the position right
after a sealed event or the anchor. It may add checkpoints but not change them,
and a trigger refuses one that is not of a sealed event's hash, is dated at an
infinite time or more than a minute ahead, or has a note over 1 KiB. It may not
move the anchor. So a compromise of auth alone
cannot rewrite, delete, reorder or backdate sealed history, nor stop sealing or
signing with a forged position, an unreadable event or a checkpoint time. The
schema owner can, by dropping the triggers; the chain is what detects that. The
database cannot check a hash or a checkpoint's signature, so that role can still
seal an event wrongly, or add a checkpoint with a forged signature; see
[Limits](#limits).

### Personal data is not covered

IP addresses, browser families and every `Personal` payload value live in
`event_personal_data`, which the chain never hashes. The stored payload holds
`"$erased"` in their place, and reads fill only those slots back in. Retention,
after 90 days, and account purges delete those rows without touching the chain.
The trade-off is that personal data is not tamper-evident. Auth's role can still
erase it, but not rewrite it: it records personal data only with its event, in
the same transaction, which a trigger checks, and an update may only remove
values.

What a sealed event holds therefore cannot be erased without breaking the chain.
Apps' related origins were held there until they became personal data: events
recorded before then keep them, in payload version 1, until the history is
pruned through them. Subject and actor IDs stay, as pseudonymous IDs, and so do
an operator's `os_user` and `host`, which are accountability data.

### Checkpoints

Every five minutes, if new events were sealed, the sealer signs a checkpoint of
the head in the C2SP signed-note format. It checks whether one is due after
every batch of 100 events, so a backlog of full batches never postpones it, and
after one fails, such as over a broken chain, it waits five minutes before trying
again:

```text
auth.piquel.fr/audit
position 48211
head 3q2+7w…
time 2026-10-13T12:00:00Z

— auth.piquel.fr/audit <base64 key ID and Ed25519 signature>
```

`head` is the base64 chain hash at `position`. The note is stored in
`audit_checkpoints`, and checkpoints are never pruned.

The sealer builds each checkpoint on the newest one that verifies against the
environment's audit keys, and its own, or on the anchor if it is newer: it
recomputes the chain from there, checking each event's hash and order. The
database cannot check signatures, so someone with auth's database role but not
the key could add a checkpoint that does not verify. The sealer logs every such
newer checkpoint as an error, counts it in
`piquel.auth.audit.untrusted_checkpoints` each time it passes over it, and
recomputes nothing while one holds the head's position. It cannot postpone
signing past the next sealed event, after which the next checkpoint follows it.
`audit verify` keeps reporting it. The sealer and `/audit/checkpoints/latest`
look past at most 1,000 of them, as many as removing a key that signed for a
few days leaves, so they never make a read costly. Past that, the sealer
recomputes from the anchor and signs above them, and the endpoint finds no
checkpoint until it has.

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

- `GET /audit/checkpoints/latest`: the signed note of the newest checkpoint that
  verifies, as the sealer checks them, as `text/plain`. A newer one that does
  not is never served as the latest.
- `GET /audit/checkpoints?after=<position>`: up to 100 checkpoints after a
  position, oldest first, as JSON `{position, hash, time, note}`, every stored
  one, for readers to verify. A position past 2^63 − 1 is refused with `400`.

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
   stored hash and each checkpoint with the recomputed head. Each event must
   also come after the previous one in the order it was recorded in,
   `(txid, sequence)`, which histories list it in.
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
| `out_of_order` | The event's recorded order does not come after the previous event's: its `txid` or `sequence` was changed to reorder history, auth's database role sealed it out of order, or the database was restored from a logical dump |
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

Every verification is recorded as an `audit_chain_verified` event, with who
made it and what it found. Auth also verifies the chain on its own: every ten
minutes one replica checks the newest recorded verification, and once it is six
hours old, whoever made it, verifies the whole chain with the dashboard's keys
(below) and records it as the `audit_verification` job. A verification that
finds the chain broken raises the `audit_chain_broken` alert for administrators,
and the next one that finds it intact clears it. One with keys given with
`--key` changes neither. The admin dashboard's
Audit tab shows the newest one and when it was made, beside the chain as stored,
so loading it costs the same however long the history. It recomputes nothing
until an administrator presses **Verify now**, which runs the same
`AdminService` operation as the CLI, within
the dashboard's 30-second request deadline, so on a very long unpruned history
use the CLI. It checks against the environment's committed key, or, on a
preview, which commits none, against the server's own key, and says so. Someone
with auth's database role can record a verification that says the chain is
intact, as they can any event, so the tab tells you what the last check found,
not that the chain is intact now: verify again before relying on it. The newest
is the one recorded last by the clock, so after the server's clock steps back the
tab can show an older one until the next verification.

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
`migrate`. Without them, `audit prune` refuses before verifying anything. In a
deployed environment, only the `migrate` job gets the owner's credentials, by
design, and piqueld runs jobs only before a rollout, so pruning there is not
supported yet: it needs a one-off job with those credentials. Until then, history
is kept. The dashboard therefore never prunes. Its Audit tab lists the
checkpoints after the anchor, says by the same rules, against the newest recorded
verification, whether the chain may be pruned through each, and shows the command
that would. The command verifies again first.

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
- **Open sessions.** Rotating the runtime role's password does not end the
  sessions already open with it, and one of them could set the role's password
  and settings again. So after a compromise, as the schema owner, first stop
  the role logging in (`ALTER ROLE piquel_auth NOLOGIN`), then end its sessions
  (`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename =
  'piquel_auth'`), then deploy with a new `database-runtime-password`, whose
  `migrate` sets it, logs the role in again and resets its settings. Auth cannot
  reach the database in between. Until then, the old sessions can still take the
  sealer's lock or hold a transaction open, which stops sealing.
- **Wrong seals.** Auth's database role seals events, so someone with it can seal
  the next event with a wrong hash, or out of order. `audit verify` reports it,
  and the sealer refuses to sign on top of it, until the schema owner repairs
  the chain. Sealing itself goes on.
- **Forged checkpoints.** Someone with auth's database role but not the audit
  key can add a checkpoint of a real sealed position and hash with a forged
  signature. `audit verify` reports it as `checkpoint_signature`, and the chain
  cannot be pruned through it, until the schema owner removes it. The sealer
  passes over it, but one that holds the newest position delays the next
  checkpoint until a new event is sealed. That role can seal events itself, so
  someone who keeps sealing one and adding a checkpoint at the new head can
  keep postponing signing while their access lasts; the sealer logs and counts
  each one.
- **Moving the database.** The order check, and the order histories list
  events in, rely on transaction IDs only ever increasing. A logical dump
  restored into a new cluster starts them again from low values, so the first
  event sealed after it would read as `out_of_order` and stop signing. Move the
  database with `pg_upgrade` or a physical copy, which keep them.
- **New events.** Someone with auth's database role can insert events, which
  are then sealed and signed like genuine ones. They are dated when inserted, so
  they cannot pass for older ones, and ordered by the transaction inserting
  them, which may have started earlier.
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
