# Handles are public

A handle names an account in public. It is the account's login name, relying
parties receive it as `preferred_username`, and published profiles will live at
`piquel.fr/@handle` ([#101](https://github.com/piquel-fr/piquel-fr/issues/101)).
Auth doesn't hide which handles have an account:

- Handle sign-in refuses a handle without an active account at once: "No active
  account has this handle." (`start_login` in `apps/auth-service/src/passkey/mod.rs`).
- Signup and renames say why a handle can't be taken, naming the look-alike
  that blocks it (`Handles::claimable` in `apps/auth-service/src/handles/mod.rs`).

This was decided in [#255](https://github.com/piquel-fr/piquel-fr/issues/255).

## Why handles aren't hidden

- **Uniqueness gives handles away.** Signup has to refuse a handle that's taken,
  and so do renames. Anyone who can sign up, or who holds an account, can
  therefore check any handle. A vaguer refusal would only stop naming the
  look-alike; it would still say the typed handle is unavailable. Production
  requires invitations, which limits signup to people with one, but open signup
  would extend this to everyone.
- **Handles are already published:** to relying parties, and in profiles once
  #101 ships.
- **Decoys hid little.** Auth used to answer handle sign-in for an unknown handle
  with stable fake credentials, derived from the token digest key. They had fixed
  shapes, one or two IDs of 16, 20 or 32 bytes, so accounts with other passkeys
  stood out. A disabled account visibly switched to decoys. Every change of
  digest key changed them, so anyone comparing responses from before and after
  learned which handles exist
  ([#181](https://github.com/piquel-fr/piquel-fr/issues/181)).

## What a handle reveals

| Who | Learns |
| --- | --- |
| Anyone, through handle sign-in | Whether the handle has an account that can sign in: one that is active, or scheduled for deletion, with a passkey. If so, that account's credential IDs too, which `WebAuthn` lists for the browser: how many passkeys it has and, from their lengths, often which provider holds them. |
| Anyone admitted to signup, and every account holder through a rename | Whether the handle, or a look-alike, is held or was held, and which look-alike. With handle sign-in, whether an account that holds it can no longer sign in. |
| Relying parties the user signs in to | The handle, as `preferred_username`. |
| Anyone, once a profile is published (#101) | The profile. An unpublished profile answers 404 like an unknown handle, so it reveals nothing beyond what sign-in does. |

The account picker (signing in without a handle) reveals nothing: the
authenticator names the account.

## Threat model

Knowing that a handle has an account gives an attacker little:

- **Nothing to guess.** Sign-in needs a passkey. A handle doesn't help forge
  one, and passkeys resist phishing.
- **No lockout.** Rate limits count requests per client IP, never per account
  (`apps/auth-service/src/security/mod.rs`), so naming an account can't lock its
  owner out.
- **Not evidence.** Support's evidence policy never counts knowing a handle
  ([account recovery](account-recovery.md#supports-evidence-policy)).
- **Credential IDs were never hidden.** Handle sign-in lists a real account's
  credential IDs with or without decoys. They only work for auth's RP ID, and
  are useless without the passkey's private key.

The cost is privacy: anyone can check whether a person, by the username they use
elsewhere, has a Piquel account. For the sign-in of piquel.fr's own apps, that
is accepted.

## Limits

- **Credential IDs link a handle across renames.** Anyone who recorded an
  account's credential IDs before a rename can find its new handle by trying
  candidates. [#297](https://github.com/piquel-fr/piquel-fr/issues/297) decides
  what to do about it.
