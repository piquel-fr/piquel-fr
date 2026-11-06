# Signing keys

Auth signs ID and access tokens with RSA keys kept in PostgreSQL, each private
key sealed with AES-256-GCM under `AUTH_KEY_ENCRYPTION_KEY`. Keys rotate without
a deploy, and every replica reloads them each minute:

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
once. One replica at a time takes each step, under a PostgreSQL advisory lock
that the `keys` commands take too. None of them needs the service running:

```sh
just auth keys list                  # IDs, states and dates
just auth keys rotate                # publish a next key; it signs in 24 hours
just auth keys rotate --now          # or sign with it at once
just auth keys revoke <id>           # delete a key at once
just auth keys digest-usage          # stored token digests per digest key
just auth keys import file:///path/key.pem   # import a PEM key into an empty key set
```

The admin dashboard's Signing keys page lists, rotates and revokes keys the same
way. Importing stays at the terminal, so the PEM private key never passes
through a browser.

`keys rotate` publishes the next key ahead of schedule. It still waits 24 hours
before signing, so no verifier meets an unknown key. `--now` skips the wait:
verifiers with a cached key set reject the new key's tokens until they fetch
keys again, which the SDKs do on an unknown `kid`, at most every 30 seconds.
Auth's own replicas reload within a minute, so until then a token from one may
fail at another.

A `next` key signs only once its private key opens and matches its public key,
checked in the transaction that promotes it. Otherwise the active key keeps
signing, every rotation attempt logs the failure, and `keys revoke <id>` removes
the bad key so rotation can publish another. Reloads also check the `next` and
`retiring` keys: one that fails is left out of JWKS and logged.

A replica that cannot reload its keys keeps the set it has, but fails readiness
after 5 minutes. After 15 minutes it stops using them: endpoints that sign or
verify answer `503`, so it never trusts a revoked key for longer than that.

## Revoking a compromised key

`keys revoke <id>` deletes the key. If it was signing, the `next` and `retiring`
keys go with it, since their private keys were stored alongside, and a new key
signs at once. This works even when the active key cannot be opened, which is
how to recover a key set whose active key is broken. Every other change first
checks that its `AUTH_KEY_ENCRYPTION_KEY` opens the active key, so check that
the command runs with the deployment's key: replacing a key with one no replica
can open makes the replicas unready until it is revoked again with the right one.
Revocation takes effect in two places, at different times:

- **At auth:** within a minute, every replica that can reload stops accepting
  the key, and one that cannot stops serving within 15 minutes, for
  access tokens at `UserInfo`, and for `id_token_hint`s. The
  tokens it legitimately signed stop working at auth too, so their users sign
  in again through SSO.
- **Downstream:** verifiers that cached JWKS keep accepting the key until their
  cache expires: up to an hour with `max-age=3600`, and longer for verifiers
  that ignore `Cache-Control`. Whoever holds the key can mint tokens with any
  `exp`, so token lifetimes do not shorten this window; only the cache does.

After revoking, restart first-party resource servers, which drops their cached
keys; the SDKs keep a known key until their cache expires. Treat the hour as
the remaining exposure at third parties.

## Changing the token digest key

Nothing rotates the token digest key; change it by hand, rarely, in two deploys,
so that during each rolling deploy, and after a rollback, every release accepts
what the other issues:

1. Set the new key as `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` and deploy.
2. Swap them: the new key as `AUTH_TOKEN_DIGEST_KEY`, the old one as
   `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, and deploy. New digests use the new key.
3. Remove `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` once `keys digest-usage` lists only
   `current`: about 30 days later, since refresh tokens end with their session,
   and a redeemed code is kept while the grant it produced lives.
   Removing it sooner ends the refresh tokens still under it.

Each stored digest records a fingerprint of its key, and `keys digest-usage`
counts them per key, until cleanup deletes them, named `current`, `accepted`, `unrecorded`
(made before fingerprints were recorded, under the old PEM signing key) or
`unknown`.
