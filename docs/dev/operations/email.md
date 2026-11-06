# Email

Auth sends through [Resend](https://resend.com)'s SMTP relay in every
environment, over implicit TLS (`smtps://resend@smtp.resend.com:465`), so a
preview sends exactly like production. Environments differ only in their sender
and key, set by the `email_from` and `smtp_secret` variables:

| Environment | Sender | Stored secret |
| --- | --- | --- |
| production | `security@piquel.fr` | `resend-production` |
| staging, previews | `security@dev.piquel.fr` | `resend-dev` |

## Keys

Each key is a Resend API key with sending access only, restricted to its domain,
so a key leaked from a preview cannot send as `piquel.fr`, and test mail never
spends production's sender reputation. piqueld does not generate these secrets:
set them by hand, before the first deployment that mounts them, which fails
without them:

```sh
piquelctl app secret piquel-fr set resend-production --stdin --environments production --no-previews
piquelctl app secret piquel-fr set resend-dev --stdin --environments staging --previews
```

Run the same command again to rotate a key; the next deployment mounts the new
one. Resend does not sign in through Piquel, so a broken auth can still email
people.

## Follow a message from a preview

To follow a message end to end from a preview, add an address at a Resend
receiving domain (`*.resend.app`, or ours with an MX record) to an account: the
message arrives in Resend's dashboard, where its link can be opened as a user
would. `delivered@resend.dev`, `bounced@resend.dev` and `complained@resend.dev`
produce those outcomes on purpose.

## DNS records

Both sending domains need three DNS records, which Resend lists for each, or
providers file the mail as spam:

- **SPF**: a TXT record on the domain listing the provider, e.g.
  `v=spf1 include:<provider's SPF domain> -all`. Keep a single SPF record: merge
  the provider's `include:` into an existing one.
- **DKIM**: the TXT or CNAME records the provider gives for its selector, e.g.
  `<selector>._domainkey.piquel.fr`, so it signs the mail for `piquel.fr`.
- **DMARC**: a TXT record at `_dmarc.piquel.fr`, starting with
  `v=DMARC1; p=quarantine; rua=mailto:<reports address>` and moving to
  `p=reject` once the reports show only aligned mail. SPF and DKIM must align with
  the `From` domain.

## Failed messages

`auth-service deliveries list --channel email --status failed` lists what did
not go out; a delivery's error is the SMTP reply code, never its text. A rejected
password (`535`) is retried for 24 hours, so mail queued while the Resend key
was wrong goes out once auth runs with the fixed secret.
