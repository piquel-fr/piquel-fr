# OIDC clients

This page helps you register the apps that sign in with Origin Auth, change them,
rotate their secrets, and stop one that misbehaves.

Clients live in the database. A change applies to the next request on every
replica, without a restart or a deployment, and is recorded as an event
attributed to you. Manage them:

- **At the terminal**, with `auth-service client` (`just auth client` locally;
  in an environment, see
  [running auth-service commands](deploying.md#running-auth-service-commands)).
- **On the admin dashboard**, on the **Clients** page.

Accounts register clients for their own apps in the developer console, at
`/developers` on auth: see [registering an app](../../user/apps/register-an-app.md)
and [clients accounts register](#clients-accounts-register).

## Register a client

At the terminal, a first-party app running in the browser:

```sh
auth-service client create blog --name Blog --trusted \
    --redirect-uri https://blog.sourceorigin.dev/callback --post-logout-uri https://blog.sourceorigin.dev/
```

An app with a server, which keeps a secret and may refresh tokens:

```sh
auth-service client create notes --name Notes --confidential --refresh \
    --redirect-uri https://notes.example/callback --scope openid --scope notes:read
```

For a confidential client, the command prints its secret once: store it in the
app's configuration straight away.

On the dashboard:

1. Open **Clients**, and select **Register a client**.
2. Fill in its **Client ID**, which never changes, and its settings.
3. Select **Register**. The next page shows a confidential client's secret,
   once.

[Settings](#settings) explains each option.

## Change a client

```sh
auth-service client show notes     # its registration and its secrets' lifetimes, as JSON
auth-service client update blog --add-redirect-uri https://blog.sourceorigin.dev/auth/callback
auth-service client update notes --backchannel-logout-uri https://notes.example/auth/backchannel-logout
```

`update` changes only what you give it. On the dashboard, open the client's
settings, change them, and select **Save changes**.

## Rotate a client's secret

1. Give the client a new secret:

   ```sh
   auth-service client rotate-secret notes --grace 24h
   ```

   On the dashboard, open the client and select **Rotate the secret**, choose
   how long **Earlier secrets keep working**, and select **Rotate secret**.
2. Store the new secret, printed once, in the app's configuration, and deploy
   the app.
3. Check with `auth-service client show notes` that the earlier secrets end
   when you expect.

The app's earlier secrets keep working for the grace period, 24 hours by
default and 30 days at most, so you can switch the app over without downtime.
`--grace 0`, or **Stop them now**, revokes them at once: for a secret that
leaked, see [a leaked client secret](incidents.md#a-leaked-client-secret).

## Disable, suspend or delete a client

- **Disable** stops the client signing users in, exchanging codes and
  refreshing tokens, at once. `client enable` undoes it.
- **Suspend** disables a client so that its owner can't enable it again until
  `client unsuspend`, which leaves it disabled. Use it for an account's client
  that breaks the rules, such as one impersonating another app. Its owner sees
  that it was suspended.
- **Delete** revokes the client's refresh tokens and removes its secrets and
  consents. Its ID stays reserved forever, since tokens carry it as `aud`, and
  its name and URIs are erased.

> **Warning:** deleting a client can't be undone.

```sh
auth-service client disable notes
auth-service client suspend notes
auth-service client delete notes
```

Each asks for confirmation. On the dashboard, open the client and select
**Disable**, **Suspend** or **Delete**.

## Apply a client a deployment manages

For a client that a deployment registers itself, run `client apply`, with the
same options as `create`, from a deployment job:

```sh
auth-service client apply blog --name Blog --confidential \
    --redirect-uri https://blog.sourceorigin.dev/callback --secret file:///run/secrets/blog-client-secret
```

It registers the client, or updates what differs, and records nothing when
nothing does, so the job can run on every deployment. Its secret comes from the
deployment, through `--secret file://<path>` or `env://<name>`: 32 random bytes
in unpadded base64url, never printed. The client's other secrets keep working
for `--grace` at most, 1 hour by default, while the deployment rolls out;
`--grace 0` revokes them. Only the terminal applies clients, since only it takes
a secret.

No deployment of SourceOrigin needs a client: the admin dashboard signs
administrators in itself (see [the admin dashboard](administration.md#how-the-dashboard-signs-administrators-in)).

## Approve an origin for passkey sign-in

A trusted client's own pages may sign users in with their passkeys, without
sending them to auth's pages, from origins you approve:

```sh
auth-service client origin add blog https://blog.sourceorigin.dev
auth-service client origin list
auth-service client origin remove blog https://blog.sourceorigin.dev
```

The client must be trusted, with a redirect URI on the origin. Approved origins
may span 5 domains at most, across every client, as browsers honour no more. On the
dashboard, open the client and select **Add approved origin** under **Passkey
sign-in**. See [passkey sign-in on your own pages](../../user/apps/passkey-sign-in.md).

## Settings

- **Kind.** Clients are public by default, and authenticate with PKCE alone
  (`none`). Confidential clients (`--confidential`) use `client_secret_basic`
  with a secret auth generates. Both require S256 PKCE.
- **Redirect URIs** must match exactly. They use HTTPS, or HTTP on a loopback IP
  for native apps, without credentials or a fragment. Write them as URL parsing
  normalizes them: `https://app.example/`, not `https://APP.example`. The
  origins of an enabled public client's redirect URIs may call the token,
  revocation and userinfo endpoints from a browser.
- **Scopes** default to `openid`, `profile` and `email`.
- **Refresh tokens** (`--refresh`) are issued when the client also requests
  `offline_access`.
- **Trusted** (`--trusted`) skips the consent screen. It is for first-party
  clients only.
- **Pushed requests** (`--require-par`) make the client push its authorization
  requests, so none of their parameters travel through the browser.
  `update --no-require-par` lifts it.
- **Back-channel logout** (`--backchannel-logout-uri`) is where auth posts a
  logout token when a session the client holds tokens from ends: see
  [back-channel logout](../../user/apps/back-channel-logout.md).

## Secrets

`create` and `rotate-secret` print a secret once, and auth stores only its
SHA-256 digest. Secrets start with `socs_`, so secret scanners can recognize
them.

## Clients accounts register

Auth generates the IDs of the clients accounts register in the developer
console, and limits their scopes to `openid`, `profile`, `email` and
`offline_access`. They are never trusted. Their names can't contain SourceOrigin's or
another well-known brand (`RESERVED_BRANDS` in `sourceorigin_common::clients`). An
account can have 10, and register 20 a day.

They never appear in other accounts' consoles, while `client list` and the
dashboard show every client. Owners can disable, enable and delete their
clients, and rotate their secrets. Deleting a client, from either side, disables
it, revokes its refresh tokens and removes its secrets and consents.
