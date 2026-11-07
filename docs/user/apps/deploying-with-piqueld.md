# Deploying with piqueld

Deploy an app that signs users in with piquel.fr on
[piqueld](https://github.com/piquel-fr/piqueld): keep its client secret in
piqueld's secret store, and give each environment its own redirect URI.

## Before you start

- You need a piqueld application for your app, with its environments, such as
  `production` and `staging`. The examples use `notes`, with a service `web`
  whose route's hostname is `${{ vars.domain }}`. piqueld's guide to
  [secrets and variables](https://github.com/piquel-fr/piqueld/blob/main/docs/user/applications/secrets-and-variables.md)
  explains the commands below in full.
- `piquelctl` must be signed in, with `secrets:write` on the application.

## Register an app per environment

[Register an app](register-an-app.md) for each environment, such as **Notes**
for production and **Notes (staging)** for staging. Each then has its own
secret, so a staging secret can't sign anyone in to production. Give each the
callback on its environment's hostname:

| Environment | Redirect URI |
| --- | --- |
| `production` | `https://notes.example/auth/callback` |
| `staging` | `https://staging.notes.example/auth/callback` |

Then give each environment its own values as manifest variables: its app's
client ID, which isn't secret, and the names of the secrets you store below.

```toml
[spec.environments.production.variables]
domain = "notes.example"
client_id = "c_…"
client_secret = "notes-client-secret"
cookie_key = "notes-cookie-key"

[spec.environments.staging.variables]
domain = "staging.notes.example"
client_id = "c_…"
client_secret = "notes-staging-client-secret"
cookie_key = "notes-staging-cookie-key"
```

## Store the client secret

piqueld gives a service each secret as a file under `/run/secrets`, never as an
environment variable.

1. Store each environment's secret, mountable by that environment only. Paste
   the secret when `piquelctl` asks for it:

   ```console
   piquelctl app secret notes set notes-client-secret --stdin --environments production --no-previews
   piquelctl app secret notes set notes-staging-client-secret --stdin --environments staging --no-previews
   ```

2. Mount the secret the environment's `client_secret` variable names in `web`,
   at the same path in every environment, with the rest of the app's settings:

   ```toml
   [[spec.services]]
   name = "web"

   [spec.services.environment]
   PIQUEL_CLIENT_ID = "${{ vars.client_id }}"
   PIQUEL_REDIRECT_URI = "https://${{ vars.domain }}/auth/callback"

   [[spec.services.secrets]]
   name = "${{ vars.client_secret }}"
   target = "/run/secrets/piquel-client-secret"
   ```

3. Read the secret from the file in your app. In Rust:

   ```rust
   let secret = std::fs::read_to_string("/run/secrets/piquel-client-secret")?;
   let credentials = Credentials::Secret(secret.trim().to_owned().into());
   ```

   In TypeScript, pass `readFileSync('/run/secrets/piquel-client-secret',
   'utf8').trim()` as the client's `clientSecret`.

4. Deploy each environment:

   ```console
   piquelctl env deploy notes staging
   piquelctl env deploy notes production
   ```

Store the key that seals the SDKs' session cookies the same way: one per
environment, mountable by that environment only, named by its `cookie_key`
variable. The cookie key seals a whole session, tokens included, so an
environment that could read another's key could forge its sessions. Generate
each with `openssl rand -base64 32`: the SDKs read standard base64, which
piqueld's generated secrets don't use.

## Rotate the secret

1. [Rotate the secret](rotate-secrets.md) in the console, with a grace period
   longer than a deployment takes.
2. Store the new secret under the same name:

   ```console
   piquelctl app secret notes set notes-client-secret --stdin
   ```

3. Deploy the environment. Running services keep the earlier secret until
   then, and it keeps working for the grace period.

## Check that it works

1. `piquelctl env show notes production` lists the mounted secret, such as
   `Secret: notes-client-secret: application store, version 1`.
2. Open the environment's hostname and sign in. Piquel's consent screen names
   that hostname, and your app receives you signed in.

## Limits

- **Redirect URIs match exactly, with no wildcards.** A preview's hostname comes
  from its slug, so every new preview has a hostname no app lists yet, and
  signing in on it fails until you register its callback. Register it on a
  development or staging app, never the production one, and remove it when you
  delete the preview. An app lists at most 16 redirect URIs.
- **Back-channel logout needs a public route.** Piquel posts logout tokens
  only to addresses on the public internet. A private route's hostname resolves
  to tailnet addresses, so an app there learns that a session ended at its next
  refresh instead, within five minutes.

## Troubleshooting

- **The deployment fails with `secret_missing` or `secret_access_denied`.** The
  secret's name is misspelled, or the environment may not mount it. See
  [piqueld's troubleshooting](https://github.com/piquel-fr/piqueld/blob/main/docs/user/applications/secrets-and-variables.md#troubleshooting).
- **Code exchanges fail with `invalid_client`.** The environment runs with
  another environment's secret, or with one whose grace period ended. Check that
  `client_id` and `client_secret` name the same app, then deploy.
- **Auth answers `redirect_uri is not registered for this client; it must match
  exactly`.** The environment's callback isn't registered on its app. On a
  preview, register the preview's hostname.
