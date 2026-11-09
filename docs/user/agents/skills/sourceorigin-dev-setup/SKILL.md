---
name: sourceorigin-dev-setup
description: >
  Run an app that signs in with sourceorigin.dev on this machine, against the real
  auth.sourceorigin.dev: a development registration with loopback redirect URIs, the
  environment variables, and a check of the sign-in from end to end. Use when
  the person wants to run, try or test their sourceorigin.dev sign-in locally.
---

# Run a sourceorigin.dev app locally

The app runs on this machine and signs in with auth.sourceorigin.dev itself. The
sign-in code comes from the sourceorigin-sign-in skill: `/auth/login`,
`/auth/callback` and `/auth/logout`, configured by `SOURCEORIGIN_CLIENT_ID`,
`SOURCEORIGIN_CLIENT_SECRET`, `SOURCEORIGIN_REDIRECT_URI` and `SOURCEORIGIN_COOKIE_KEY`.

Registering an app: https://docs.sourceorigin.dev/user/apps/register-an-app.html

## 1. Choose the local address

Pick a fixed port, such as 3000, and use `127.0.0.1`, not `localhost`:

- Auth accepts plain HTTP only on a loopback IP, such as
  `http://127.0.0.1:3000/auth/callback` or `http://[::1]:3000/auth/callback`.
  It refuses `http://localhost/...`.
- Auth compares the redirect URI as a whole string, port included, so the app
  must always run on the port that was registered.
- Open the app at the same host as the redirect URI. The cookie of a sign-in in
  progress is set for the host the browser started on, so a sign-in started on
  `localhost` fails on the `127.0.0.1` callback.

## 2. Ask the person for a development registration

Registering needs a passkey confirmation, which only the person can give. Ask
them to register a separate app for development at
https://auth.sourceorigin.dev/developers/new, so the production secret never reaches
this machine:

- **App name**: such as `Notes (development)`.
- **Does your app have a backend that can keep a secret?**: **Yes, a web app
  with a backend**.
- **Redirect URIs**: `http://127.0.0.1:3000/auth/callback`.
- **Post-logout URIs**: `http://127.0.0.1:3000/`, if the app sends users back
  there after signing out.
- **Scopes**: the app's scopes, and `offline_access`, which the SDKs' login
  routes always request.
- **Allow refresh tokens**: checked.
- **Back-channel logout URI**: empty. Auth posts logout tokens only to HTTPS
  URIs with public addresses, so it can't reach this machine.

An account can have 10 apps at once.

## 3. Set the environment

Make sure the file holding local settings, such as `.env`, is in `.gitignore`
first. Then:

- Generate the cookie key yourself: `openssl rand -base64 32`.
- Set `SOURCEORIGIN_REDIRECT_URI=http://127.0.0.1:3000/auth/callback`.
- Ask the person to add `SOURCEORIGIN_CLIENT_ID` and `SOURCEORIGIN_CLIENT_SECRET`
  themselves. The console showed the secret once, after **Register app**. If it
  is lost, they rotate it on the app's **Secrets** tab.

## 4. Check the sign-in

1. Check that auth answers discovery, with the issuer the app uses:

   ```console
   curl -s https://auth.sourceorigin.dev/.well-known/openid-configuration
   ```

   Its `issuer` is `https://auth.sourceorigin.dev`.

2. Start the app, then start a sign-in without a browser:

   ```console
   curl -si http://127.0.0.1:3000/auth/login
   ```

   The SDK pushes the sign-in request to auth first, with the client ID, the
   secret, the redirect URI and the scopes. A `303` to
   `https://auth.sourceorigin.dev/oauth/authorize` with a `request_uri` means auth
   accepted all of them. A `502` that starts `Sign-in could not start:` names
   what auth refused: use the sourceorigin-debug-sign-in skill.

3. Ask the person to open `http://127.0.0.1:3000/auth/login` in their browser,
   sign in with their passkey and approve the consent page, which labels the
   app "Unverified app, registered by" their handle. They land back on the
   app, signed in.

4. Ask them to sign out through the app. They land on the post-logout URI the
   app names, or on auth's own page if it names none.
