# Signing keys

This page helps you check, rotate and revoke the keys auth signs ID and access
tokens with, and change the key-encryption key and the token digest key.

Auth keeps its RSA signing keys in PostgreSQL, each private key sealed with
AES-256-GCM under `AUTH_KEY_ENCRYPTION_KEY`. They rotate on their own, without a
deployment: a new key is published a day before it signs, and an old one stays
published while tokens it signed may still be in use (see
[how keys rotate](#how-keys-rotate)).

None of the `keys` commands needs the service running. In an environment, run
them with `piquelctl app exec` (see
[running auth-service commands](deploying.md#running-auth-service-commands)), and
locally with `just auth keys …`. The admin dashboard's **Signing keys** page
lists, rotates, revokes and rewraps keys too.

## Check the signing keys

```sh
auth-service keys list
```

The command prints each key's ID, type and state, and when it was created,
started signing, stopped signing and was retired, oldest first. One key is
`active`. Usually a `next` key waits too, and a `retiring` one follows a
rotation.

Every change to a key is recorded as a `signing_key_changed` event:

```sh
auth-service audit list --kind signing_key_changed
```

Each event says who made the change: an operator, with their reason, or the
key rotation job, for the steps rotation takes on its own. On the dashboard,
filter the **Events** page by the same kind; each event there also names the
key and what happened to it.

## Rotate a key ahead of schedule

To replace the active key before its 90 days are up:

- **At the terminal**, run `auth-service keys rotate --reason "…"`. It prints
  the new key's ID.
- **On the dashboard**, select **Rotate** on the **Signing keys** page, give a
  reason, and confirm.

Either publishes a `next` key, which starts signing in 24 hours, so every
verifier has fetched it first. A key already waiting is kept.

## Rotate at once

Only the terminal rotates at once:

```sh
auth-service keys rotate --now --reason "…"
```

The new key signs straight away. Verifiers with a cached key set reject its
tokens until they fetch keys again, which the SDKs do on an unknown `kid`, at
most every 30 seconds. Auth's own replicas reload within a minute, so until then
a token from one may fail at another. Prefer the 24-hour rotation unless the
active key must stop signing now; for a compromised key, revoke it instead.

## Revoke a key

> **Warning:** revoking deletes the key at once, and can't be undone.

- **At the terminal**, run `auth-service keys revoke <id> --reason "…"`.
- **On the dashboard**, select **Revoke** next to the key on the **Signing
  keys** page, give a reason, and confirm.

When the revoked key was signing, the `next` and `retiring` keys go with it,
since their private keys were stored beside it, and a new key signs at once.
Every replica stops accepting the tokens it signed within a minute, or within
15 minutes if it can't reload its keys (see
[how replicas load keys](#how-replicas-load-keys)). For a key that may be in
someone else's hands, follow
[a compromised signing key](incidents.md#a-compromised-signing-key).

## Replace a key that doesn't open

A `next` key signs only once its private key opens and matches its public key,
which the promotion checks. Otherwise the active key keeps signing, and every
rotation attempt logs the failure.

1. Find the key in `auth-service keys list`, and the failure in auth's logs.
2. Revoke it with `auth-service keys revoke <id> --reason "…"`, so rotation can publish
   another.

Revoking works even when the active key can't be opened, which is how to
recover a key set whose active key is broken: revoke the active key, and a new
one signs. Every other change first checks that its `AUTH_KEY_ENCRYPTION_KEY`,
or its `AUTH_KEY_ENCRYPTION_KEY_ACCEPTED`, opens the active key. So run the
command with the deployment's own keys: a key sealed with one no replica can
open makes the replicas unready, until you revoke it again with the right one.

## Change the key-encryption key

Auth seals every signing key's private key under the key-encryption key,
`AUTH_KEY_ENCRYPTION_KEY`. Nothing changes it on its own. Change it by hand, in
two deployments, so that during each rolling deployment, and after a rollback,
every release opens the keys the other seals. A third deployment then removes
the old key.

Each step is a change to `infra/piqueld.toml`, which reaches staging when it
merges and production when you [promote](deploying.md#promote-to-production).
Take each step in every environment before the next.

1. Add the new key as accepted. Declare a generated secret for it, mount it in
   `auth`, and point `AUTH_KEY_ENCRYPTION_KEY_ACCEPTED` at it:

   ```toml
   [[spec.secrets]]
   name = "key-encryption-key-2"
   generate = { type = "random", bytes = 32, encoding = "base64url" }

   [spec.services.environment]
   AUTH_KEY_ENCRYPTION_KEY_ACCEPTED = "file:///run/secrets/key-encryption-key-2"

   [[spec.services.secrets]]
   name = "key-encryption-key-2"
   target = "/run/secrets/key-encryption-key-2"
   ```

   Deploy. Auth now opens keys sealed under either key, and still seals under
   the old one.
2. Swap them: point `AUTH_KEY_ENCRYPTION_KEY` at the new key's file, and
   `AUTH_KEY_ENCRYPTION_KEY_ACCEPTED` at the old one's. Deploy. New keys are
   sealed under the new key.
3. Once that deployment has finished, seal every stored key again under the new
   key:
   - **At the terminal**, run `auth-service keys rewrap --reason "…"`. It asks
     you to confirm, then lists the keys it rewrapped.
   - **On the dashboard**, select **Rewrap** on the **Signing keys** page, give
     a reason, and confirm.

   Each key it rewraps records a `rewrapped` change. If a key opens under
   neither key, it changes nothing and names that key: revoke it, then rewrap
   again.
4. Remove `AUTH_KEY_ENCRYPTION_KEY_ACCEPTED`, and the old key's mount and
   declaration, and deploy. Then delete the old secret in each environment:

   ```sh
   piquelctl env secret sourceorigin --env production delete key-encryption-key
   ```

Don't rewrap while replicas of the deployment before step 2 still run: they
keep sealing new keys under the old key. If a key still opens only under the old
key at step 4, the new replicas fail to start, so the rollout fails (see
[roll back production](deploying.md#roll-back-production)). Rewrap again, then
deploy.

> **Warning:** once you have rewrapped, never restore a deployment made before
> step 1: it has only the old key, and opens none of the keys.

For a key that leaked, see
[a leaked key-encryption key](incidents.md#a-leaked-key-encryption-key).

## Change the token digest key

Auth stores refresh tokens, authorization codes and pending logins as HMAC
digests under the token digest key, and email verification, recovery,
unsubscribe, sign-out and invitation links derive from it (see [configuration](configuration.md)). Nothing rotates it.
Change it by hand, rarely, in two deployments, so that during each rolling
deployment, and after a rollback, every release accepts what the other issues:

1. Set the new key as `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, and deploy.
2. Swap them: the new key as `AUTH_TOKEN_DIGEST_KEY`, and the old one as
   `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`. Deploy. New digests use the new key.
3. Wait until `auth-service keys digest-usage` lists only `current` keys:
   about 30 days, since refresh tokens end with their session, and a redeemed
   code is kept while the grant it produced lives.
4. Remove `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, and deploy. Removing it sooner ends
   the refresh tokens still under it. Announcements' unsubscribe links made under
   the old key stop working then, whenever it is removed: their owners turn the
   email off in their settings instead. `digest-usage` doesn't count
   invitations: also wait until every invitation created before step 2 has
   expired or been revoked. A mailed link already delivered keeps working, but
   one still queued, or sent again with **Resend**, is rebuilt under the old
   key, and fails without it. Revoke such an invitation and invite again
   instead.

In the manifest, each key is a generated secret mounted as a file, as
`token-digest-key` is (see [secrets](secrets.md#generated-secrets)).

For a key that leaked, replace it at once instead: see
[a leaked token digest key](incidents.md#a-leaked-token-digest-key).

## How keys rotate

| State | Signs | In JWKS | Its tokens verify | Lasts |
| --- | --- | --- | --- | --- |
| `next` | no | yes | yes | 24 hours, then it signs |
| `active` | yes | yes | yes | 90 days, then a `next` key is published |
| `retiring` | no | yes | yes | 65 minutes: the 5-minute token lifetime plus the JWKS cache lifetime |
| `retired` | no | no | as `id_token_hint` only | 30 days, the longest session, then it is deleted with its public key |

JWKS is served with `Cache-Control: public, max-age=3600`, so a `next` key is
published long before any verifier needs it. A retired key's private key is
erased, but logout and authorization still accept the expired ID tokens it
signed as hints. On first start with no keys, auth generates one that signs at
once.

One replica at a time takes each step, under a PostgreSQL advisory lock that the
`keys` commands take too (see [background jobs](replicas.md#background-jobs)).

## How replicas load keys

Every replica reloads the key set each minute. A reload also checks the `next`
and `retiring` keys: one that fails to open is left out of JWKS, and logged.

A replica that can't reload its keys keeps the set it has, but fails readiness
after 5 minutes. After 15 minutes it stops using them: endpoints that sign or
verify answer `503`, so it never trusts a revoked key for longer than that.

## Token digest usage

`auth-service keys digest-usage` counts the stored digests per kind of record
and per key, until cleanup deletes them. It names each key:

- `current`: `AUTH_TOKEN_DIGEST_KEY`.
- `accepted`: `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`.
- `unrecorded`: made before digests recorded their key's fingerprint.
- `unknown`: neither configured key.
