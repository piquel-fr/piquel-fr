# Email addresses

This page explains how auth stores an account's email addresses, verifies them,
keeps verified ownership unique, and sends mail. Read it before changing
anything under `apps/auth-service/src/emails` or the `email` delivery channel.

## Data model

| Table | Holds |
| --- | --- |
| `user_emails` | an account's addresses, each normalized, with when it was verified and whether it is primary |
| `email_verification_secrets` | the SHA-256 digest of an unverified address's link token, and when it expires |
| `active_verified_email_ownership` | one row per verified address of an active account, naming that account |

Addresses are compared as `NormalizedEmail` (`sourceorigin_common::email`), whose rules
[email normalization](../security/email-normalization.md) sets out.

The schema holds the invariants itself:

- **One primary verified address per account**, by a unique partial index. The
  OIDC `email` claim reports that address, and an account without one has no
  `email` claim.
- **A verified address belongs to one active account.** Triggers on `user_emails`
  and on account status keep `active_verified_email_ownership` in step, and
  verifying an address another active account verified fails as a unique
  violation. Disabling an account releases its addresses, and enabling it again
  fails if another account claimed one meanwhile. An account scheduled for
  deletion keeps its verified addresses, so nobody claims them before it is
  restored or purged.
- **An unverified address waits for its link.** Verifying it deletes its
  secret, under the account's lock. Once the link expires, the cleanup job deletes
  the address with its secret.

## Operations

The operations are on `AccountService` (`src/emails/mod.rs`). Adding and
verifying are owner-only, through `EmailApplication`'s routes; listing, choosing
the primary and removing are shared settings that administrators and operators
also run, with the same notices
([changing an account on its owner's behalf](surfaces.md#changing-an-account-on-its-owners-behalf)).

- **Add** (`add_email`) takes an `Owner` whose passkey confirmation is checked
  under the account lock. It inserts the address unverified, records
  `EmailAdded`, stores the digest of its link token for 24 hours
  (`VERIFICATION_LIFETIME`) and queues its link, in one transaction. Adding an
  address that is already waiting replaces it, which sends a new link. An address
  another account verified can be added, so adding reveals nothing about other
  accounts; only verification finds out. An account holds at most 10 addresses.
- **Verify** (`verify_email`) takes the link's token, not a session: holding it
  proves control of the mailbox. A browser signed in to another account is
  refused, since it would confirm the address for an account that is not its own.
  It records `EmailVerified`, and `PrimaryEmailChanged` when the address becomes
  the account's first primary. The settings page verifies only when its button is
  pressed, since mail scanners follow links.
- **Choose the primary** (`make_primary_email`) and **remove** (`remove_email`)
  need the owner's recent passkey confirmation, or an administrator's own and
  their reason. A
  removal is recorded before the row is deleted, so the `email` channel still
  reads the address and copies it into the notice of its removal. The primary
  address can only be removed once no other verified address could replace it.
- **Import** (`EmailApplication::import`), during a GitHub or Google sign-up or
  link, adds the provider's address to an account that has no verified one. It
  arrives verified and primary only when the provider hosts the mailbox
  (`email_authoritative`: Gmail, or the account's Google Workspace domain), and
  otherwise unverified, with a link, since it may have changed owners. An address
  another account verified, one too many, or one whose link can't be sent now is
  skipped: signing in matters more.

### Limits

Every verification email counts against three hourly budgets, in the transaction
that queues it, so a refused or failed addition counts nothing (`EmailApplication::limit`):

| Budget | Per hour |
| --- | --- |
| the account | 5 |
| the client IP | 10 |
| the mailbox, whatever the case and `+` tag of its address | 3 |

They share the rate-limit table of the [request budgets](request-lifecycle.md#rate-limit),
under keys of their own.

## Links

A verification link opens `/settings/emails/verify#token=…`. Its token is never
stored, not even in the delivery that sends it: it is an HMAC of the address's
ID under the verification key (`VerificationKeys`), derived from the token
digest key. Settings store only its SHA-256 digest when the address is added,
and the email sender derives the token again when it sends the link
([token digest keys](keys.md#token-digest-keys)).

## Sending

Auth sends email only through the [delivery queue](delivery-queue.md#email),
never from a request. A verification link's delivery stores the address's ID,
not the address: the sender reads it when it sends, so a link to an address
removed, replaced or verified meanwhile, or of an account no longer active, is
not sent. Notices about addresses are [notifications](notifications.md), emailed
to the address they concern.

Messages are transactional security notices: no tracking, no remote images, and
links only to auth's pages. Without `AUTH_SMTP_URL`, adding an address is refused,
an import skips its address, and the delivery workers drop what is queued. Any
SMTP provider works, as long as it does not depend on SourceOrigin's own sign-in;
[email](../operations/email.md) describes the deployments' relay and its DNS
records. For development, `just auth mailpit` runs a local Mailpit: set
`AUTH_SMTP_URL=smtp://localhost:1025` and read the mail at
`http://localhost:8025`.
