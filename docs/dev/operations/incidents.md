# Incidents

This page helps you respond when something goes wrong in staging or production:
a key or secret leaks, an administrator account is in the wrong hands, auth goes
down, or mail stops going out. Each runbook says how you notice, what to do in
order, and how to check that it's over.

Run every `auth-service` command below in the affected environment, with
`piquelctl app exec -t sourceorigin auth --env production -- auth-service --operator <you> …` (see
[running auth-service commands](deploying.md#running-auth-service-commands)).
`-t` gives the command a terminal: most commands below ask you to confirm what
they will change, and refuse without one. The
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

piqueld may also still store an environment's old `signing-key` secret, which
nothing mounts any more: `piquelctl env secret sourceorigin --env <env> list`
lists it. It holds the private key of `primary`, the key it was imported as,
in plaintext PEM. If that value leaks, `primary` is compromised on its own:
revoke it if `keys list` still lists it, then delete the secret with
`piquelctl env secret sourceorigin --env <env> delete signing-key`.

### What to do

1. If whoever holds them may still read the database or the host, close that
   access first. The key-encryption key can't be changed: it seals every key
   auth generates, including the one that replaces the revoked key. So someone
   who holds it and reads the database again can open the new key too.
2. Find the key to revoke: the one in state `active`, or `primary` when only
   the stored `signing-key` secret leaked:

   ```sh
   auth-service keys list
   ```

3. Revoke it:

   ```sh
   auth-service keys revoke <id> --reason "Compromised"
   ```

   On the dashboard, select **Revoke** next to it on the **Signing keys** page.
   When the revoked key was `active`, the `next` and `retiring` keys go with it,
   since their private keys were stored beside it, and a new key signs at once.
   Revoking any other key removes only that key.
4. Wait 15 minutes after the revocation. Each replica serves its own copy of
   the key set and reloads it each minute, and one that can't reload stops
   serving within 15 minutes, so only then has every replica dropped the
   revoked keys. `https://auth.sourceorigin.dev/.well-known/jwks.json` no longer
   listing them shows only that the replica that answered has.
5. Then restart the first-party resource servers, which drops the keys they
   cached. Restarting sooner could cache the revoked keys again from a replica
   that still serves them. The SDKs keep a known key until their cache expires,
   so other verifiers may accept the revoked keys for up to an hour from this
   point.

Every access and ID token the revoked keys signed stops working at auth,
including as an `id_token_hint`. Refresh tokens don't depend on signing keys, so
apps refresh and receive tokens signed by the new key.

### Check that it's over

- `auth-service keys list` lists none of the revoked keys, and a new `active`
  key if you revoked the active one.
- `https://auth.sourceorigin.dev/.well-known/jwks.json` no longer lists their IDs.
- An hour after step 5, verifiers that respect `Cache-Control` have dropped them. Until
  then, whoever holds a revoked key can mint tokens that third parties accept,
  with any `exp`, so token lifetimes don't shorten this window. Verifiers that
  ignore `Cache-Control` may accept them longer.

[Signing keys](signing-keys.md) explains revocation and reloads.

## A leaked client secret

### How you notice

A secret starting with `socs_` appears where it shouldn't: in a repository, a
log, a ticket or a message. Secret scanners recognize the prefix. The app's
owner may report it too.

With the secret, someone can authenticate as the app at the token endpoint,
with a code or a refresh token the app was given.

### What to do

1. Find the client the secret belongs to, with the app's owner, or in
   `auth-service client list`.
2. Revoke every earlier secret at once, and get a new one:

   ```sh
   auth-service client rotate-secret <client-id> --grace 0 --reason "Secret leaked"
   ```

   On the dashboard, open the client, select **Rotate the secret**, choose
   **Stop them now** for **Earlier secrets keep working**, and select **Rotate
   secret**. For an account's client, its owner can do the same on its
   **Secrets** tab in the developer console.

   The app can't sign anyone in until it has the new secret.
3. Give the app the new secret, printed once, and deploy it. For a client a
   deployment registers with `client apply`, regenerate the deployment's secret
   instead: its next `client apply` would register the leaked value again.
4. If more than the secret leaked, such as the app's server with the refresh
   tokens it holds, also stop the client until the server is clean:
   `auth-service client disable <client-id> --reason "…"` stops it from authorizing and
   refreshing tokens at once. Deleting the client revokes its refresh tokens for
   good (see [OIDC clients](clients.md#disable-suspend-or-delete-a-client)).

### Check that it's over

- `auth-service client show <client-id>` lists the new secret without an end,
  and every earlier one ending at the rotation.
- The app signs users in again.

## A leaked token digest key

### How you notice

The `token-digest-key` secret, `AUTH_TOKEN_DIGEST_KEY`, appears outside the
environment: in a backup, a log, or on a compromised host.

Auth stores refresh tokens, authorization codes and pending logins as HMAC
digests under this key, and email verification, recovery and unsubscribe links
derive from it. With the key and the ID of an address, a recovery or an account,
someone can rebuild the link auth sent for it. An unsubscribe link only turns
that account's announcements' email off, but it never expires.

### What to do

The usual change takes two deployments and keeps the old key accepted for about
30 days (see [changing the token digest key](signing-keys.md#change-the-token-digest-key)).
For a leaked key, replace it at once instead:

1. Generate a new key:

   ```sh
   piquelctl env secret sourceorigin --env production regenerate token-digest-key
   ```
2. Deploy production's own release again, as
   [pick up a changed secret](deploying.md#pick-up-a-changed-secret-in-production)
   describes. For staging, run `piquelctl --timeout 30m env deploy sourceorigin staging`.

   Every refresh token, code and login in progress under the old key ends, so
   apps sign their users in again. During the rollout, each release refuses what
   the other issued.
3. Deal with the recoveries started in the last day, which
   `auth-service audit list --kind recovery_started` lists. For each account,
   run `auth-service user undo-recovery <user> --reason "…"` without `--yes`:
   it prints the account's recent recoveries with where each stands, then asks
   to confirm what it will do.
   - If the recovery says **link not used**, and the prompt says it will cancel
     its unused link, confirm. Start a new recovery with `auth-service user
     recover` once the new key is deployed: the new link derives from it.
   - If the link was used since the leak, the passkey it enrolled may be the
     attacker's. Don't confirm: undoing removes that passkey and every session,
     which locks the account holder out if the passkey was theirs. Ask the
     holder, through a channel support already trusts, whether they used it,
     and undo it only if they didn't.

Links already sent are checked against the digest stored when they were made,
so they keep working until they expire, within 24 hours. That includes the
links that confirm an email address: for that day, someone with the old key
could confirm an address an account added but hasn't confirmed yet.
Unsubscribe links are checked by deriving them again, so those built from the
old key stop working once the new key replaces it.

### Check that it's over

- `auth-service keys digest-usage` counts new digests under `current`, and the
  old ones as `unknown` until cleanup deletes them.
- 24 hours have passed since the deployment, so every link derived from the
  old key has expired.

## A leaked database password

### How you notice

The `database-password` secret, the superuser `sourceorigin`'s password, or
`database-runtime-password`, `sourceorigin_auth`'s, appears outside the
environment: in a backup, a log, or on a compromised host.

PostgreSQL answers only on the application's private network, so the password
alone doesn't open it. With a way onto that network too, the superuser's
password reads and changes everything in the database, and the runtime role's
reads and changes the accounts and sessions auth stores.

### What to do

1. If whoever holds it may still reach the host or the application's network,
   close that access first.
2. A new password doesn't undo what someone who connected as the superuser left
   behind. A superuser can run commands as PostgreSQL's system user and change
   any file in its volume, so no check proves the database clean. If someone
   did connect, load a copy of the database made before the leak into a new
   volume: a dump or a volume backup, not `piquelctl env restore`, which keeps
   the volume. If you have none, or can't tell whether anyone connected, check
   at least these before you rotate. Compare each with the same query on a
   fresh preview, whose database is new, run with
   `piquelctl preview exec sourceorigin <branch> postgres -- psql -U sourceorigin -d sourceorigin -c "…"`:
   - The roles that can log in:

     ```sh
     piquelctl app exec sourceorigin postgres --env <environment> -- psql -U sourceorigin -d sourceorigin -c "SELECT rolname FROM pg_roles WHERE rolcanlogin"
     ```

     Only `sourceorigin` and `sourceorigin_auth` should. Remove any other with
     `REASSIGN OWNED BY <role> TO sourceorigin` and `DROP OWNED BY <role>` in
     each database, then `DROP ROLE <role>`.
   - The authentication rules, from `SELECT * FROM pg_hba_file_rules`, run the
     same way. Every column must match the preview's, masks included.
   - The server settings, from
     `SELECT sourcefile, name, setting FROM pg_file_settings`. One from
     `postgresql.auto.conf` came from `ALTER SYSTEM`, which SourceOrigin never
     uses: run `ALTER SYSTEM RESET ALL`.
   - Settings stored on a database or role, from `SELECT * FROM pg_db_role_setting`,
     and event triggers, from `SELECT evtname, evtevent FROM pg_event_trigger`.
     Both are empty on a new database.

   Anything else that differs from the preview's means a changed file or
   catalog: load a copy from before the leak instead.
3. Generate a new value for the secret that leaked:

   ```sh
   piquelctl env secret sourceorigin --env <environment> regenerate database-password
   ```

   For `database-runtime-password`, regenerate that one instead.
4. Deploy production's own release again, as
   [pick up a changed secret](deploying.md#pick-up-a-changed-secret-in-production)
   describes. For staging, run `piquelctl --timeout 30m env deploy sourceorigin staging`.

   For the superuser's password, PostgreSQL restarts with the new one before
   `migrate` runs. For the runtime role's, `migrate` sets the new one, and
   connections already open with the old one stay open until they close. See
   [the database password](secrets.md#the-database-password) and
   [the database runtime password](secrets.md#the-database-runtime-password).
5. If someone may have connected:
   - Check that they didn't rewrite the history with `auth-service audit verify`.
   - The superuser could also have changed any row, such as an administrator
     grant or a client's redirect URIs, without leaving an event. If you can't
     rule that out, load a copy from before the leak, as step 2 says.
   - If they could also have read the `key-encryption-key` secret, follow
     [a compromised signing key](#a-compromised-signing-key).

### Check that it's over

- The deployment succeeded: its `migrate` job logged in with the new value.
- `piquelctl env secret sourceorigin --env <environment> list` shows the new
  version of the secret.
- If someone may have connected, the database was loaded from a copy made
  before the leak, or its login roles, authentication rules, settings and event
  triggers match a fresh preview's.

## A stolen administrator session or a compromised administrator account

### How you notice

- The [Admin activity](telemetry.md#watch-administrator-activity) dashboard
  shows changes nobody you know made: rights granted, accounts disabled or
  viewed, refused sign-ins.
- An owner asks about a change "By a SourceOrigin administrator" in their security
  history that they never asked for.
- An administrator finds an entry in their own security history that isn't
  theirs, and reports it, which signs out their other sessions.
  `auth-service audit list --kind compromise_reported` lists these reports.
- `auth-service admin list` lists an administrator nobody granted.
- An alert says **The audit chain is broken** or **The audit chain's
  checkpoints stopped**: someone changed the history (see
  [respond to an alert](administration.md#respond-to-an-alert)).

### What to do

Act at the terminal: the dashboard never changes an administrator's account,
while the command line may.

1. Revoke the account's rights, which ends its dashboard access on its next
   request:

   ```sh
   auth-service admin revoke <handle> --reason "Account compromised"
   ```

   If it holds the last rights, first grant them to an account you trust with
   `auth-service admin grant <handle> --reason "…"`.
2. End its sessions, which ends its dashboard session with them:

   ```sh
   auth-service session revoke-all <handle> --reason "Account compromised"
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

- auth.sourceorigin.dev answers errors, or nothing, and users report it.
- `https://auth.sourceorigin.dev/health/ready` doesn't answer `204`. It checks the
  database and that the replica's signing keys were reloaded recently.
- `piquelctl env show sourceorigin production` reports a service unhealthy.
- The Auth overview dashboard's **Server errors** rise. Grafana keeps working,
  since it never signs in through auth (see
  [sign in to Grafana](telemetry.md#sign-in-to-grafana)).

### What to do

1. See what piqueld sees:

   ```sh
   piquelctl env history sourceorigin production
   piquelctl env logs sourceorigin production --service auth --since-seconds 900
   ```

2. If a deployment caused it, return to the previous one. When its rollout
   failed, production already restored the last successful deployment on its
   own. Otherwise, restore it: see
   [roll back production](deploying.md#roll-back-production).
3. Read Grafana's Auth overview: **Server errors**, **Database connections**
   and **Logs**.
4. If the replicas aren't ready because of the database, read
   `piquelctl env logs sourceorigin production --service postgres`.
5. If they aren't ready because of their signing keys, the logs say which key
   failed. A replica that can't reload its keys fails readiness after 5 minutes,
   and answers `503` where it signs or verifies after 15. A key that won't open
   is removed with `auth-service keys revoke <id> --reason "…"`, which works even when the
   active key can't be opened (see
   [replace a key that doesn't open](signing-keys.md#replace-a-key-that-doesnt-open)).

Meanwhile, every administrative operation runs at the terminal: the command
line is the break-glass path when the dashboard or auth's pages are
unreachable. `piquelctl app exec` needs a running auth container: if none
runs, restore a deployment first. Nothing auth runs on needs auth to sign in: piqueld, the servers, the
tailnet, PostgreSQL, DNS, the tunnel, Grafana and Resend (see
[recovering auth](../architecture/surfaces.md#recovering-auth)).

### Check that it's over

- `piquelctl --timeout 10m env wait sourceorigin production --ready routes`
  returns: the deployment runs healthy, and every route answers. It waits for
  the deployment that was newest when it started, so if that one failed and
  production rolled back, check
  `piquelctl env history sourceorigin production` and
  `piquelctl env url sourceorigin production` instead.
- `https://auth.sourceorigin.dev/health/ready` answers `204`.
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
   auth-service deliveries retry <id> --reason "Mail back up"
   ```

   A retry makes the delivery due now, and gives it another 24 hours. On the
   dashboard's **Deliveries** page, select **Retry**.

Mail that arrives but lands in spam points at the
[DNS records](email.md#dns-records), not the queue.

### Check that it's over

- The `email` channel's **Pending deliveries** are back to their usual level.
- New deliveries in `auth-service deliveries list --channel email` are
  `succeeded`, and Resend's dashboard lists the messages as delivered.
