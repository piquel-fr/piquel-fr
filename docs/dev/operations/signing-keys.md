# Signing keys

This page helps you check, rotate and revoke the keys auth signs ID and access
tokens with, and change the token digest key.

Auth keeps its RSA signing keys in PostgreSQL, each private key sealed with
AES-256-GCM under `AUTH_KEY_ENCRYPTION_KEY`. They rotate on their own, without a
deployment: a new key is published a day before it signs, and an old one stays
published while tokens it signed may still be in use (see
[how keys rotate](#how-keys-rotate)).

None of the `keys` commands needs the service running. In an environment, run
them with `piquelctl app exec` (see
[running auth-service commands](deploying.md#running-auth-service-commands)), and
locally with `just auth keys …`. The admin dashboard's **Signing keys** page
lists, rotates and revokes keys too.

## Check the signing keys

```sh
auth-service keys list
```

The command prints each key's ID, type and state, and when it was created,
started signing, stopped signing and was retired, oldest first. One key is
`active`. Usually a `next` key waits too, and a `retiring` one follows a
rotation.

## Rotate a key ahead of schedule

To replace the active key before its 90 days are up:

- **At the terminal**, run `auth-service keys rotate`. It prints the new key's
  ID.
- **On the dashboard**, select **Rotate** on the **Signing keys** page, and
  confirm.

Either publishes a `next` key, which starts signing in 24 hours, so every
verifier has fetched it first. A key already waiting is kept.

## Rotate at once

Only the terminal rotates at once:

```sh
auth-service keys rotate --now
```

The new key signs straight away. Verifiers with a cached key set reject its
tokens until they fetch keys again, which the SDKs do on an unknown `kid`, at
most every 30 seconds. Auth's own replicas reload within a minute, so until then
a token from one may fail at another. Prefer the 24-hour rotation unless the
active key must stop signing now; for a compromised key, revoke it instead.

## Revoke a key

> **Warning:** revoking deletes the key at once, and can't be undone.

- **At the terminal**, run `auth-service keys revoke <id>`.
- **On the dashboard**, select **Revoke** next to the key on the **Signing
  keys** page, and confirm.

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
2. Revoke it with `auth-service keys revoke <id>`, so rotation can publish
   another.

Revoking works even when the active key can't be opened, which is how to
recover a key set whose active key is broken: revoke the active key, and a new
one signs. Every other change first checks that its `AUTH_KEY_ENCRYPTION_KEY`
opens the active key. So run the command with the deployment's own key: a key
sealed with one no replica can open makes the replicas unready, until you revoke
it again with the right one.

## Import a key

```sh
auth-service keys import file:///path/key.pem
```

The command imports a PEM RSA key as the active key, named `primary` unless
`--id` names it, so tokens it signed keep verifying. It imports only into an
empty key set, and otherwise changes nothing. Every deployment runs it as the
`signing-key-import` job, with the `signing-key` secret. The dashboard never
imports, so the private key never passes through a browser.

## Change the token digest key

Auth stores refresh tokens, authorization codes and pending logins as HMAC
digests under the token digest key, and email verification, recovery and
unsubscribe links derive from it (see [configuration](configuration.md)). Nothing rotates it.
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
   email off in their settings instead.

In the manifest, each key is a generated secret mounted as a file, as
`token-digest-key` is. `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` holds the `signing-key`
secret until no digest remains under it, so a change starts once that secret is
removed (see [secrets](secrets.md#generated-secrets)).

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
- `unrecorded`: made before digests recorded their key's fingerprint, under the
  old PEM signing key.
- `unknown`: neither configured key.
