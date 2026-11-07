# Email

This page helps you keep auth's mail going out: set up a sending domain, rotate
the Resend keys, and follow a message end to end. When mail stops, see
[mail not going out](incidents.md#mail-not-going-out).

Auth sends through [Resend](https://resend.com)'s SMTP relay in every
environment, over implicit TLS (`smtps://resend@smtp.resend.com:465`), so a
preview sends exactly like production. Environments differ only in their sender
and key, which the `email_from` and `smtp_secret` variables set:

| Environment | Sender | Stored secret |
| --- | --- | --- |
| production | `security@piquel.fr` | `resend-production` |
| staging, previews | `security@dev.piquel.fr` | `resend-dev` |

Each key is a Resend API key with sending access only, restricted to its
domain. So a key leaked from a preview can't send as `piquel.fr`, and test mail
never spends production's sender reputation. Resend doesn't sign in through
Piquel, so auth can still email people while it is broken.

## Set up a sending domain

1. Add the domain to Resend: `piquel.fr` for production, `dev.piquel.fr` for
   staging and previews.
2. Create the domain's [DNS records](#dns-records), and wait for Resend to
   verify them.
3. Create an API key with sending access, restricted to the domain.
4. Store it before the first deployment that mounts it, which fails without it:

   ```sh
   piquelctl app secret piquel-fr set resend-production --stdin --environments production --no-previews
   piquelctl app secret piquel-fr set resend-dev --stdin --environments staging --previews
   ```

## Rotate a Resend key

1. In Resend, create a new API key with sending access, restricted to the same
   domain. Keep the old key for now.
2. Store it under the same name, with the same access, as in
   [set up a sending domain](#set-up-a-sending-domain).
3. Deploy the environments that mount it. For `resend-production`, promote
   production (see [promote to production](deploying.md#promote-to-production)).
   For `resend-dev`, run `piquelctl --timeout 30m env deploy piquel-fr staging`;
   each preview uses the new key from its next deployment.
4. Check that mail goes out: the newest deliveries in
   `auth-service deliveries list --channel email` are `succeeded`, and Resend's
   dashboard lists the messages.
5. Delete the old key in Resend.

A preview still running the old key fails to send once it is deleted, until the
preview deploys again. Its messages wait and retry for 24 hours (see
[delivery and retries](#delivery-and-retries)).

## Follow a message from a preview

1. Add an address at a Resend receiving domain, `*.resend.app` or one of ours
   with an MX record, to an account on the preview.
2. Open the message in Resend's dashboard, and follow its link as a user would.

`delivered@resend.dev`, `bounced@resend.dev` and `complained@resend.dev` produce
those outcomes on purpose.

## DNS records

Both sending domains need three kinds of DNS records, which Resend lists for
each, or providers file the mail as spam:

- **SPF**: a TXT record on the domain listing the provider, such as
  `v=spf1 include:<provider's SPF domain> -all`. Keep a single SPF record:
  merge the provider's `include:` into an existing one.
- **DKIM**: the TXT or CNAME records the provider gives for its selector, such
  as `<selector>._domainkey.piquel.fr`, so it signs the mail for the domain.
- **DMARC**: a TXT record at `_dmarc.piquel.fr`, starting with
  `v=DMARC1; p=quarantine; rua=mailto:<reports address>`. Move to `p=reject`
  once the reports show only aligned mail. SPF and DKIM must align with the
  `From` domain.

## Delivery and retries

Auth queues every message as a delivery, which a worker sends (see
[the delivery queue](../architecture/delivery-queue.md#email)).

- A permanent (5xx) SMTP reply fails the delivery.
- A temporary (4xx) reply, a rejected login (`530`, `534`, `535`), a timeout, or
  a connection or TLS failure is retried, for up to 24 hours. So mail queued
  while the Resend key was wrong goes out once auth runs with the right one.
- A delivery's recorded error is the SMTP reply code, never its text, which can
  quote the recipient.

`auth-service deliveries list --channel email --status failed` lists what didn't
go out, and the Auth overview dashboard's **Deliveries** row charts the queue
(see [telemetry](telemetry.md#dashboards)).
