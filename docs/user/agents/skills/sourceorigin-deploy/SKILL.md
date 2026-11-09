---
name: sourceorigin-deploy
description: >
  Deploy an app that signs in with Origin Auth on piqueld: its client secret and
  cookie key as piqueld secrets, a redirect URI for each environment, and a
  check of the sign-in once it is deployed. Use when the person wants to ship,
  deploy or host their Origin Auth app with piqueld or piquelctl.
---

# Deploy an Origin Auth app on piqueld

The app signs in with the SDKs' login routes, from the sourceorigin-sign-in skill,
and reads `SOURCEORIGIN_CLIENT_ID`, `SOURCEORIGIN_REDIRECT_URI`, and the client secret and
cookie key from `SOURCEORIGIN_CLIENT_SECRET_FILE` and `SOURCEORIGIN_COOKIE_KEY_FILE`.
piqueld puts each secret in a read-only file under `/run/secrets`, never in an
environment variable.

The guides behind this skill:

- Registering an app: https://docs.sourceorigin.dev/user/apps/register-an-app.html
- piqueld secrets: https://docs.piqueld.dev/user/applications/secrets-and-variables.html
- piqueld environments: https://docs.piqueld.dev/user/applications/environments.html
- piqueld routes: https://docs.piqueld.dev/user/networking/routes.html

## 1. Ask the person for a registration per environment

Each environment has its own host, so its own redirect URI. Give each its own
registration, so a staging secret can't sign users in to production. Only the
person can register them: the developer console asks for a passkey
confirmation. For each environment, ask them to register an app at
https://auth.sourceorigin.dev/developers/new, with:

- **Does your app have a backend that can keep a secret?**: **Yes, a web app
  with a backend**.
- **Redirect URIs**: `https://<environment's host>/auth/callback`.
- **Post-logout URIs**: `https://<environment's host>/`, if the app sends
  users back there after signing out.
- **Scopes**: the app's scopes, and `offline_access`.
- **Allow refresh tokens**: checked.
- **Back-channel logout URI**:
  `https://<environment's host>/auth/backchannel-logout`, only if the app
  handles back-channel logout.

They give you each **Client ID**, which is public.

## 2. Configure the service

In the manifest, give each environment its values, and mount the secrets in
the app's service. Here the service is `web`, on port 3000:

```toml
[spec.environments.staging.variables]
domain = "staging.notes.example.com"
sourceorigin_client_id = "<staging client ID>"
sourceorigin_client_secret = "sourceorigin-client-secret-staging"
sourceorigin_cookie_key = "sourceorigin-cookie-key-staging"

[spec.environments.production.variables]
domain = "notes.example.com"
sourceorigin_client_id = "<production client ID>"
sourceorigin_client_secret = "sourceorigin-client-secret-production"
sourceorigin_cookie_key = "sourceorigin-cookie-key-production"

[[spec.services]]
name = "web"
# ...

[spec.services.environment]
SOURCEORIGIN_CLIENT_ID = "${{ vars.sourceorigin_client_id }}"
SOURCEORIGIN_REDIRECT_URI = "https://${{ vars.domain }}/auth/callback"
SOURCEORIGIN_CLIENT_SECRET_FILE = "/run/secrets/sourceorigin-client-secret"
SOURCEORIGIN_COOKIE_KEY_FILE = "/run/secrets/sourceorigin-cookie-key"

[[spec.services.secrets]]
name = "${{ vars.sourceorigin_client_secret }}"
target = "/run/secrets/sourceorigin-client-secret"

[[spec.services.secrets]]
name = "${{ vars.sourceorigin_cookie_key }}"
target = "/run/secrets/sourceorigin-cookie-key"

[spec.services.healthcheck]
type = "http"
port = 3000
path = "/health"

[[spec.routes]]
name = "web"
hostname = "${{ vars.domain }}"
service = "web"
port = 3000
visibility = "public"
```

- In the container, the app must listen on `0.0.0.0`, not `127.0.0.1`, for the
  route to reach it.
- The health check's path must answer without a session. A page that takes
  `SignedIn` answers piqueld's check with 401, which fails it, and the app the
  sourceorigin-sign-in skill builds has no such route yet: add a `/health` route
  outside the login layer that answers 200 or 204.
- The variables are runtime settings, not build arguments, so an environment
  promoted from staging can run staging's image.

Check the manifest, then save it. Saving creates the environments it
declares, without deploying them:

```console
piquelctl app validate --file infra/piqueld.toml
piquelctl app apply --file infra/piqueld.toml
```

## 3. Store the secrets

Ask the person to store each environment's client secret themselves, so it
never passes through you. In a terminal, `--stdin` asks for the value without
showing it:

```console
piquelctl app secret <app> set sourceorigin-client-secret-production --stdin --environments production --no-previews
piquelctl app secret <app> set sourceorigin-client-secret-staging --stdin --environments staging
```

Each environment also needs its own cookie key, never shared: the key seals
whole sessions, tokens included, so an environment that could read another's
key could forge its users' sessions. It is 32 random bytes in standard base64.
piqueld's generated secrets are hexadecimal or base64url, which the SDKs refuse,
so store them instead. You can run these: the values go straight into piqueld.

```console
openssl rand -base64 32 | piquelctl app secret <app> set sourceorigin-cookie-key-production --stdin --environments production --no-previews --yes
openssl rand -base64 32 | piquelctl app secret <app> set sourceorigin-cookie-key-staging --stdin --environments staging --yes
```

## 4. Deploy

```console
piquelctl --timeout 5m env deploy <app> staging
piquelctl --timeout 5m env deploy <app> production
```

A deployment that mounts a secret with no value fails with `secret_missing`,
and leaves the running services as they were.

Previews may not mount stored secrets unless the person allows them with
`piquelctl app secret <app> access <name> --previews`, and each preview's host
would need its own registered redirect URI. Ask the person before you give
previews sign-in.

## 5. Check it after deploying

1. Check that the route is ready:

   ```console
   piquelctl env url <app> production
   ```

2. Start a sign-in without a browser:

   ```console
   curl -si https://notes.example.com/auth/login
   ```

   A `303` to `https://auth.sourceorigin.dev/oauth/authorize` with a `request_uri`
   means auth accepted the client ID, the secret, the redirect URI and the
   scopes. A `502` that starts `Sign-in could not start:` names what it
   refused: use the sourceorigin-debug-sign-in skill.

3. Read the service's output if it fails to start, for example when a secret
   file is missing:

   ```console
   piquelctl env logs <app> production --service web
   ```

4. Ask the person to sign in on the deployed app with their passkey.

## Rotating the client secret

The person rotates it on the app's **Secrets** tab in the developer console,
keeping the earlier secret working for a while, then stores the new one with
`piquelctl app secret <app> set` and deploys. Running services keep the old
value until the next deployment.
