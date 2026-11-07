# Incidents

This page helps you respond when something goes wrong in staging or production:
a key or secret leaks, an administrator account is in the wrong hands, auth goes
down, or mail stops going out. Each runbook says how you notice, what to do in
order, and how to check that it's over.

Run every `auth-service` command below in the affected environment, with
`piquelctl app exec piquel-fr auth --env production -- auth-service …` (see
[running auth-service commands](deploying.md#running-auth-service-commands)). The
command line needs only the database, so it works while auth's pages and the
admin dashboard don't.

> **Warning:** after rotating a secret, never [restore](deploying.md#roll-back-production)
> a deployment made before the rotation: a restore, like an automatic rollback,
> brings back the secret versions it ran with. Watch the deployment that rotates
> it, and fix forward if it fails.

## A compromised signing key

### How you notice

A signing key's private key opens only with both the database and the
key-encryption key (`AUTH_KEY_ENCRYPTION_KEY`). Treat every stored key as
compromised when both may have leaked: a copy of the database and the
`key-encryption-key` secret together, or a host that runs auth.

### What to do

1. If whoever holds them may still read the database or the host, close that
   access first. The key-encryption key can't be changed: it seals every key
   auth generates, including the one that replaces the revoked key. So someone
   who holds it and reads the database again can open the new key too.
2. Find the active key, the one in state `active`:

   ```sh
   auth-service keys list
   ```

3. Revoke it:

   ```sh
   auth-service keys revoke <id>
   ```

   On the dashboard, select **Revoke** next to it on the **Signing keys** page.
   The `next` and `retiring` keys go with it, since their private keys were
   stored beside it, and a new key signs at once. A retired key's private key is
   already erased.
4. Restart the first-party resource servers, which drops the keys they cached.
   The SDKs keep a known key until their cache expires.

Every token the revoked keys signed stops working at auth, so their users sign
in again through SSO.

### Check that it's over

- `auth-service keys list` shows a new `active` key, and none of the revoked
  ones.
- `https://auth.piquel.fr/.well-known/jwks.json` no longer lists their IDs.
- An hour later, verifiers that respect `Cache-Control` have dropped them. Until
  then, whoever holds a revoked key can mint tokens that third parties accept,
  with any `exp`, so token lifetimes don't shorten this window. Verifiers that
  ignore `Cache-Control` may accept them longer.

[Signing keys](signing-keys.md) explains revocation and reloads.

## A leaked client secret

### How you notice

A secret starting with `pqcs_` appears where it shouldn't: in a repository, a
log, a ticket or a message. Secret scanners recognize the prefix. The app's
owner may report it too.

With the secret, someone can authenticate as the app at the token endpoint,
with a code or a refresh token the app was given.

### What to do

1. Find the client the secret belongs to, with the app's owner, or in
   `auth-service client list`.
2. Revoke every earlier secret at once, and get a new one:

   ```sh
   auth-service client rotate-secret <client-id> --grace 0
   ```

   On the dashboard, open the client, select **Rotate the secret**, choose
   **Stop them now** for **Earlier secrets keep working**, and select **Rotate
   secret**. For an account's client, its owner can do the same on its
   **Secrets** tab in the developer console.

   The app can't sign anyone in until it has the new secret.
3. Give the app the new secret, printed once, and deploy it.
4. If more than the secret leaked, such as the app's server with the refresh
   tokens it holds, also stop the client until the server is clean:
   `auth-service client disable <client-id>` stops it from authorizing and
   refreshing tokens at once. Deleting the client revokes its refresh tokens for
   good (see [OIDC clients](clients.md#disable-suspend-or-delete-a-client)).

### Check that it's over

- `auth-service client show <client-id>` lists one secret, the new one, without
  an end.
- The app signs users in again.

## A leaked token digest key

### How you notice

The `token-digest-key` secret, `AUTH_TOKEN_DIGEST_KEY`, appears outside the
environment: in a backup, a log, or on a compromised host.

Auth stores refresh tokens, authorization codes and pending logins as HMAC
digests under this key, and email verification and recovery links derive from
it. With the key and the ID of an address or a recovery, someone can rebuild
the link auth sent for it.

### What to do

The usual change takes two deployments and keeps the old key accepted for about
30 days (see [changing the token digest key](signing-keys.md#change-the-token-digest-key)).
For a leaked key, replace it at once instead:

1. Generate a new key:

   ```sh
   piquelctl env secret piquel-fr --env production regenerate token-digest-key
   ```

   If the `signing-key` secret leaked with it, regenerate it too: it is the
   accepted key, `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`. It is also the RSA key
   imported as `primary`, so if `auth-service keys list` still lists `primary`
   unretired, revoke it as [a compromised signing key](#a-compromised-signing-key)
   describes.
2. Deploy production by [promoting](deploying.md#promote-to-production) staging.
   For staging, run `piquelctl --timeout 30m env deploy piquel-fr staging`.

   Every refresh token, code and login in progress under the old key ends, so
   apps sign their users in again. During the rollout, each release refuses what
   the other issued.
3. Cancel the recovery links still in flight. List the recoveries of the last
   day with `auth-service audit list --kind recovery_started`, and cancel each
   unused link with `auth-service user undo-recovery <user> --reason "…"`. Start
   it again with `auth-service user recover` once the new key is deployed: the
   new link derives from the new key.

Links already sent are checked against the digest stored when they were made,
so they keep working until they expire, within 24 hours.

### Check that it's over

- `auth-service keys digest-usage` counts new digests under `current`, and the
  old ones as `unknown` until cleanup deletes them.
- 24 hours have passed since the deployment, so every link derived from the
  old key has expired.

## A stolen administrator session or a compromised administrator account

### How you notice

- The [Admin activity](telemetry.md#watch-administrator-activity) dashboard
  shows changes nobody you know made: rights granted, accounts disabled or
  viewed, refused sign-ins.
- An owner asks about a change "By a Piquel administrator" in their security
  history that they never asked for.
- An administrator finds an entry in their own security history that isn't
  theirs, and reports it, which signs out their other sessions.
  `auth-service audit list --kind compromise_reported` lists these reports.
- `auth-service admin list` lists an administrator nobody granted.

### What to do

Act at the terminal: the dashboard never changes an administrator's account,
while the command line may.

1. Revoke the account's rights, which ends its dashboard access on its next
   request:

   ```sh
   auth-service admin revoke <handle>
   ```

   If it holds the last rights, first grant them to an account you trust with
   `auth-service admin grant <handle>`.
2. End its sessions, which ends its dashboard session with them:

   ```sh
   auth-service session revoke-all <handle>
   ```

3. If the account's passkey may be in someone else's hands, not just a session,
   stop it signing in while you find out:

   ```sh
   auth-service user disable <handle> --reason "Compromised administrator account"
   ```

   Then return the account to its owner, following the evidence policy: enable
   it, since a recovery needs an active account, and recover it with `--revoke`
   (see [recover an account someone else held](administration.md#recover-an-account-someone-else-held)).
4. Find what it did: **Actions by administrator** and **Administrative events**
   on the Admin activity dashboard, the dashboard's **Events** page, and
   `auth-service audit list`, such as `--kind administrator_granted`.
5. Undo each change: revoke the rights it granted, enable the accounts it
   disabled, lift the suspensions it made, and undo the recoveries it started
   with `auth-service user undo-recovery`.
6. Verify that the history you relied on is intact, from a trusted build:

   ```sh
   auth-service audit verify
   ```

A change made at the terminal records its operator's `$USER` and host name. One
that nobody made points at a compromised host: treat the secrets on it as
leaked, starting with the runbooks above.

### Check that it's over

- `auth-service admin list` lists only the administrators you expect.
- `auth-service account <handle> sessions list` lists no session you don't
  recognize.
- The Admin activity dashboard shows only work you know of.
- `auth-service audit verify` reports the chain intact.

## Auth is down

### How you notice

- auth.piquel.fr answers errors, or nothing, and users report it.
- `https://auth.piquel.fr/health/ready` doesn't answer `204`. It checks the
  database and that the replica's signing keys were reloaded recently.
- `piquelctl env show piquel-fr production` reports a service unhealthy.
- The Auth overview dashboard's **Server errors** rise. Grafana keeps working,
  since it never signs in through auth (see
  [sign in to Grafana](telemetry.md#sign-in-to-grafana)).

### What to do

1. See what piqueld sees:

   ```sh
   piquelctl env history piquel-fr production
   piquelctl env logs piquel-fr production --service auth --since-seconds 900
   ```

2. If a deployment caused it, return to the previous one. When its rollout
   failed, production already restored the last successful deployment on its
   own. Otherwise, restore it: see
   [roll back production](deploying.md#roll-back-production).
3. Read Grafana's Auth overview: **Server errors**, **Database connections**
   and **Logs**.
4. If the replicas aren't ready because of the database, read
   `piquelctl env logs piquel-fr production --service postgres`.
5. If they aren't ready because of their signing keys, the logs say which key
   failed. A replica that can't reload its keys fails readiness after 5 minutes,
   and answers `503` where it signs or verifies after 15. A key that won't open
   is removed with `auth-service keys revoke <id>`, which works even when the
   active key can't be opened (see
   [replace a key that doesn't open](signing-keys.md#replace-a-key-that-doesnt-open)).

Meanwhile, every administrative operation runs at the terminal: the command
line is the break-glass path when the dashboard or auth's pages are
unreachable. `piquelctl app exec` needs a running auth container: if none
runs, restore a deployment first. Nothing auth runs on needs auth to sign in: piqueld, the servers, the
tailnet, PostgreSQL, DNS, the tunnel, Grafana and Resend (see
[recovering auth](../architecture/surfaces.md#recovering-auth)).

### Check that it's over

- `piquelctl --timeout 10m env wait piquel-fr production --ready routes`
  returns: the deployment runs healthy, and every route answers.
- `https://auth.piquel.fr/health/ready` answers `204`.
- **Server errors** on the Auth overview dashboard are back to their usual
  level.

## Mail not going out

### How you notice

- Users don't receive verification, recovery or notice emails.
- On the Auth overview dashboard's **Deliveries** row, the `email` channel's
  **Pending deliveries** grow, its **Oldest pending delivery** gets older, and
  **Delivery attempts** show retries or failures.

### What to do

1. List what is waiting and what failed:

   ```sh
   auth-service deliveries list --channel email --status pending
   auth-service deliveries list --channel email --status failed
   ```

   Each delivery's last error is the SMTP reply code.
2. Fix the cause the code points at:
   - **`535`, `530` or `534`**: Resend rejected the key. Store a working one, as
     [rotate a Resend key](email.md#rotate-a-resend-key) describes. Rejected
     logins retry for 24 hours, so mail queued meanwhile goes out once auth runs
     with the new key.
   - **Another `5xx`**: Resend refused the message for good, and the delivery
     failed. Check the sending domain's status and its
     [DNS records](email.md#dns-records) in Resend's dashboard.
   - **A timeout, or a connection or TLS failure**: auth can't reach Resend.
     Check Resend's status, and auth's logs.
3. Once the cause is fixed, retry the failed deliveries still worth sending:

   ```sh
   auth-service deliveries retry <id>
   ```

   A retry makes the delivery due now, and gives it another 24 hours. On the
   dashboard's **Deliveries** page, select **Retry**.

Mail that arrives but lands in spam points at the
[DNS records](email.md#dns-records), not the queue.

### Check that it's over

- The `email` channel's **Pending deliveries** are back to their usual level.
- New deliveries in `auth-service deliveries list --channel email` are
  `succeeded`, and Resend's dashboard lists the messages as delivered.
