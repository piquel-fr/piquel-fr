# Keys

This page explains the keys auth holds and what each one protects: the signing
keys, which live in PostgreSQL and rotate by themselves, the token digest keys
and what derives from them, and the audit key. The procedures for rotating,
revoking and changing them are in [signing keys](../operations/signing-keys.md).

| Key | Where it lives | Protects | Changes |
| --- | --- | --- | --- |
| Signing keys | `signing_keys`, sealed under the key-encryption key | ID, access and logout tokens | rotate every 90 days by themselves |
| Key-encryption key | `AUTH_KEY_ENCRYPTION_KEY` | the signing keys' private keys at rest | cannot be changed yet |
| Token digest keys | `AUTH_TOKEN_DIGEST_KEY`, and `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` during a change | stored opaque tokens, and email verification, recovery and unsubscribe links | by hand, in two deploys |
| Audit key | `AUTH_AUDIT_KEY_PROVIDER` | the audit chain's checkpoints | by hand |

Every replica must run with the same keys. The keys are read in
`apps/auth-service/src/config/keys.rs`; the cryptography is in `piquel-crypto`.

## Signing keys

Auth signs tokens with RS256 keys. `apps/auth-service/src/keys` holds two types:

- `KeyStore` is the keys in the database: it lists them, makes every change to
  them, and seals and opens their private keys. The `keys` commands use it
  without the HTTP service.
- `SigningKeys` is the key set one replica signs and verifies with: a
  `piquel_crypto::KeySet` shared by every clone, which a reload replaces for all
  of them at once. A request keeps the set it started with.

### Storage

Each row of `signing_keys` holds a key ID of 22 random base64url characters, its
type, its state, its public key as a JWK, and its private key in DER, sealed with
AES-256-GCM under the key-encryption key (`KeyEncryptionKey`). A sealed value is
the nonce, the ciphertext and the tag, and its associated data is the key's ID
and type, so a sealed key moved to another row fails to open. Opening a key also
checks that the private key is the half of the public key stored with it.

The database never sees a private key in the clear. Retiring a key erases its
private key; only its public key stays, to verify hints.

### States and rotation

```text
next ──24 h──▶ active ──90 days──▶ retiring ──65 min──▶ retired ──30 days──▶ deleted
 published      signs, published    published             verifies hints only
```

The table allows one `active` and one `next` key per key type.
[Signing keys](../operations/signing-keys.md) says why each state lasts as long
as it does.

`Change::advance` takes the step rotation needs now, if any:

- With no key at all, a key is generated and signs at once: the first start.
- Once the active key is 90 days old, a `next` key is generated.
- Once `next` has been published for 24 hours, it is promoted: it signs, and the
  active key becomes `retiring`. Promotion first opens `next` and checks its
  public key, so a key that cannot sign is refused, logged, and the active key
  keeps signing.
- `retiring` keys become `retired`, and `retired` ones are deleted, once their
  window passed.

`KeyStore::start` runs a step on startup, waiting for any change in progress, then
loads the key set. After that, `KeyStore::run`, a job on every replica, tries a
step each minute, then reloads the key set. A step runs in a transaction that
holds `signing_keys().try_lock()`, a transaction-level advisory lock, so one
replica at a time takes it and the others skip it; the `keys` commands wait for
the same lock (`signing_keys().lock()`). Before any change, `KeyStore::check`
makes sure this key-encryption key opens the stored active key, so a replica or
command with the wrong key never stores keys nobody can open.

Changes an operator makes, from `auth-service keys` or the dashboard's Signing
keys page, record `SigningKeyChanged`. Rotation by the service itself only logs
`signing key changed`.

### Reload and readiness

`KeyStore::key_set` builds a replica's key set from the stored keys: the active
key signs, `next` and `retiring` keys are published in JWKS and verify, and
`retired` keys verify `id_token_hint`s only, which may be expired. A `next` or
`retiring` key that cannot be opened is left out and logged; an active key that
cannot be opened fails the reload.

A failed reload keeps the current set in use, while it is fresh enough:

- After five minutes without a reload, `/health/ready` fails
  (`SigningKeys::ready`), so traffic moves to replicas that can reload.
- After fifteen minutes, `SigningKeys::current` returns `StaleKeys`, so every
  endpoint that signs or verifies answers `503`. A replica never trusts a revoked
  key for longer than that.

The key set signs and verifies for `OidcApplication` (tokens, JWKS, userinfo and
hints) and for `BackchannelLogoutSender`, which signs each logout token when it
sends it.

## Token digest keys

Opaque tokens are stored as HMAC digests, never as themselves: pending
authorizations, authorization codes and refresh tokens
([opaque tokens](oidc.md#opaque-tokens)). `TokenDigestKeys` holds the current key,
which makes every new digest, and, during a change, an accepted one, which only
checks digests. A presented token is looked up by its digest under each.

`TokenDigestKey::derive` derives four keys from the configured bytes, each with
HMAC-SHA256 under a context of its own, so none can stand in for another:

- **The token digest key itself.** Its fingerprint, the first 8 bytes of its
  SHA-256 in base64url, is stored with each digest, which `keys digest-usage`
  counts.
- **The email verification key** (`VerificationKeys` in `src/emails`).
- **The recovery link key** (`RecoveryLinks` in `src/recovery`).
- **The unsubscribe link key** (`UnsubscribeLinks` in `src/notifications`).

The verification and recovery keys are `LinkKeys`. A link's token is an HMAC of the ID of what it acts
on, an address or a recovery, under the current link key. Auth stores only the
token's SHA-256 digest, and the email sender derives the token again when it
sends the link, so the token is never stored, not even in the
[delivery](delivery-queue.md#email). During a change of token digest key, the
sender rebuilds a queued link under whichever configured key derives its stored
digest, and a link already sent keeps working, since it is checked against that
digest.

An unsubscribe link's token is the HMAC of the account's ID under the
unsubscribe link key. It is stored nowhere: auth checks a link by deriving the
token again under the current key and the accepted one. So it never expires, and
stops working only once neither configured key derives it. Holding one only
turns that account's announcements' email off (see
[email preferences](notifications.md#email-preferences)).

Other secrets need no key: session cookies, the browser binding of passkey
ceremonies, dashboard handoff codes and restore offers are random, and stored as
plain SHA-256 digests.

## The audit key

The audit chain's checkpoints are signed notes, with an Ed25519 key of their own
(`AuditConfig`), so it rotates independently of the signing keys. The variable
holds its 32-byte seed in hex, and the key is named `<auth host>/audit`. The
sealer job signs a checkpoint with it; the database never sees it. Its public
key is committed as `docs/dev/security/audit-key.pub`, which
`auth-service keys audit` prints.
[The audit key](../security/audit-history.md#the-audit-key) and
[rotating the audit key](../security/audit-history.md#rotating-the-audit-key)
explain the rest.
