---
name: sourceorigin-debug-sign-in
description: >
  Find out why a sign-in with sourceorigin.dev fails: read the error the app or SDK
  got, check auth.sourceorigin.dev's discovery and the app's registration (client ID,
  secret, redirect URIs, scopes), and fix the common causes. Use when signing
  in with sourceorigin.dev fails, loops, ends too soon, or answers an error such as
  invalid_client, invalid_scope or "Sign-in could not start".
---

# Debug a sourceorigin.dev sign-in

Work from the error the person or the app saw. Most failures come from a
registration that doesn't match the app's configuration: `SOURCEORIGIN_CLIENT_ID`,
`SOURCEORIGIN_CLIENT_SECRET`, `SOURCEORIGIN_REDIRECT_URI` and the scopes.

The guides behind this skill:

- Registering an app: https://docs.sourceorigin.dev/user/apps/register-an-app.html
- OpenID Connect reference: https://docs.sourceorigin.dev/user/reference/oidc.html

## 1. Read the error

The SDKs' login routes answer with a short text that says where the sign-in
stopped:

| Answer | What happened |
| --- | --- |
| `502` from `/auth/login`: `Sign-in could not start: the pushed authorization endpoint rejected the request with <error>.` | Auth refused the request before the browser left the app. Step 3 reads why |
| `502` from `/auth/login`: `Sign-in could not start: request to <url> failed.` | The app could not reach auth |
| `400` from `/auth/callback`: `Sign-in failed: ... authorization failed with access_denied.` | The person declined the consent page |
| `400` from `/auth/callback`: `This sign-in has no pending login; start again.` | The browser didn't bring back the cookie of the sign-in it started. See the causes below |
| `400` from `/auth/callback`: `This sign-in expired; start again.` | The sign-in took more than 10 minutes |
| `502` from `/auth/callback`: `Signing in could not end your previous session; start again.` | Auth was unreachable while the app revoked the session this sign-in replaces |
| The app fails to start: `metadata names issuer ..., expected ...` | `SOURCEORIGIN_ISSUER` differs from auth's issuer, for example by a trailing slash |
| The app fails to start: `environment variable not found` | A variable is missing from the app's environment |
| The app fails to start: `the login routes need a confidential client` (Rust), or a `TypeError` from `new Login` (TypeScript) | No client secret reached the SDK |
| The app fails to start: `a cookie key must be standard base64` or `a cookie key must hold 32 bytes` | Make a key with `openssl rand -base64 32` |

An app that doesn't use the SDKs may show auth's own answer in the browser
instead, a JSON object such as
`{"error":"invalid_request","error_description":"redirect_uri is not registered for this client; it must match exactly"}`.

## 2. Check discovery

```console
curl -s https://auth.sourceorigin.dev/.well-known/openid-configuration
```

The SDKs require its `issuer`, `https://auth.sourceorigin.dev`, to equal the issuer
the app discovers, character for character.

## 3. Read auth's reason

The SDKs' message names the error code only. Send the app's request yourself
to read auth's description. Run it where the app's environment is set, and
don't print the secret. On piqueld, the secret is in the file
`SOURCEORIGIN_CLIENT_SECRET_FILE` names rather than in `SOURCEORIGIN_CLIENT_SECRET`:

```console
secret="${SOURCEORIGIN_CLIENT_SECRET:-$(cat "$SOURCEORIGIN_CLIENT_SECRET_FILE")}"
curl -s -u "$SOURCEORIGIN_CLIENT_ID:$secret" https://auth.sourceorigin.dev/oauth/par \
  --data-urlencode response_type=code \
  --data-urlencode "redirect_uri=$SOURCEORIGIN_REDIRECT_URI" \
  --data-urlencode "scope=openid profile offline_access" \
  --data-urlencode code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  --data-urlencode code_challenge_method=S256
```

Put the scopes the app requests in `scope`: the SDKs' login routes always add
`openid` and `offline_access`. A `request_uri` in the answer means auth accepts
the request, and it expires unused after 60 seconds. Otherwise the answer
names the problem:

| `error` | `error_description` | Fix |
| --- | --- | --- |
| `invalid_client` | `client_id is not a registered, enabled client` | Wrong client ID, or the app is disabled, suspended or deleted |
| `invalid_client` | `the client secret is incorrect or expired` | Wrong secret, or one replaced by a rotation whose grace period ended |
| `invalid_client` | `this public client must not send HTTP Basic credentials` | The app was registered without a backend. The login routes need one with a secret: register a new app, since the kind never changes |
| `invalid_request` | `redirect_uri is not registered for this client; it must match exactly` | Compare `SOURCEORIGIN_REDIRECT_URI` with the registration |
| `invalid_scope` | `scope includes values this client may not request` | The registration doesn't allow every scope, often `offline_access` |

## 4. Compare with the registration

You can't open the developer console: ask the person to open the app from
https://auth.sourceorigin.dev/developers and read you its overview, which holds
nothing secret. Its **Client authentication** is `client_secret_basic` for an
app with a backend. Compare its **Client ID**, **Scopes** and **Redirect URIs**
with the app's configuration, character for character: the scheme, the host,
the port, the path and any trailing slash.

Changing the registration needs a passkey confirmation, so the person makes
the change, on the app's **Settings** tab.

## Common causes

- **`localhost` instead of `127.0.0.1`.** Auth accepts plain HTTP only on a
  loopback IP, such as `http://127.0.0.1:3000/auth/callback`. Open the app at
  the redirect URI's host too: a sign-in started on `localhost` has no pending
  login on the `127.0.0.1` callback.
- **Another port.** The redirect URI is compared with its port.
- **`offline_access` missing.** The login routes request it on every sign-in.
- **Sessions end after about five minutes.** **Allow refresh tokens** is off:
  a session without a refresh token lasts as long as its access token.
- **The wrong environment's values.** Each environment's registration has its
  own client ID, secret and redirect URI.
- **An old secret.** After a rotation, earlier secrets work only for the grace
  period chosen. The person rotates again on the **Secrets** tab if the
  current one is lost.
- **Several sign-ins at once.** A browser keeps up to three sign-ins in
  progress, in slots their `state` picks. A sign-in that lands in a taken slot
  replaces the one there, whose callback then has no pending login.
