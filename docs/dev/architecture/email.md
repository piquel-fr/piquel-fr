# Email addresses

Accounts add, verify, choose the primary of and remove their addresses on
`auth.piquel.fr/settings/emails`; the OIDC `email` claim reports the primary verified
address. Adding an address sends a link to `settings/emails/verify#token=…`,
which works once for 24 hours. The page verifies only when its button is pressed,
since mail scanners follow links, and needs no session. Adding an address,
changing the primary one and removing one need a passkey confirmation, like other
sensitive changes. An account sends at most 5 verification emails an hour, a
client IP at most 10, and one mailbox, whatever the case and `+` tag of its
address, receives at most 3. An address another active account verified cannot be
verified again; adding it is allowed, so adding reveals nothing. The email names
the account the address would join, and a browser signed in to another account
cannot confirm it. An address that stops being primary, or is removed, is told,
as every notification is emailed: see [notifications](notifications.md).
Signing up or linking with GitHub or Google imports the provider's address into an
account without a verified one, recorded in its history as imported. It arrives
verified only where the provider hosts the mailbox, Gmail and the account's
Google Workspace domain; any other address arrives unverified with a link, since
it may have changed owners. An address another account verified, or whose link
can't be sent now, is skipped.

## Sending

Auth sends email through the [delivery queue](delivery-queue.md#email), never from a request. Messages are
transactional security notices: no tracking, no remote images, and links only to
auth's settings pages. Without `AUTH_SMTP_URL`, adding an address is refused and
queued messages are dropped. Any SMTP provider works; deployments use Resend's
relay, as [email](../operations/email.md) describes. The provider must not depend on Piquel's own
sign-in. For development, `just auth mailpit` runs a local Mailpit: set
`AUTH_SMTP_URL=smtp://localhost:1025` and read the mail at
`http://localhost:8025`. Sending domains need SPF, DKIM and DMARC; see
[DNS records](../operations/email.md#dns-records).
