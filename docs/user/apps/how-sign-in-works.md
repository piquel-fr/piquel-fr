# How sign-in works

This page covers what you need to know before you sign users in to your own app
with their piquel.fr account, and which SDK to pick. The
[OpenID Connect reference](../reference/oidc.md) has the details.

## auth.piquel.fr is an OpenID Connect provider

Your app sends the user to auth.piquel.fr. The user signs in there with a passkey,
GitHub or Google, and auth sends them back to your app with a one-time code. Your
app then exchanges the code for tokens. This is OpenID Connect's authorization
code flow, with PKCE.

Any OpenID Connect library sets itself up from the issuer, `https://auth.piquel.fr`.
It reads the endpoints from the discovery document at
`https://auth.piquel.fr/.well-known/openid-configuration`.

## Apps

An app, which OpenID Connect calls a client, is what you register in the
[developer console](register-an-app.md). Auth gives it a client ID. An app is one
of two kinds, and its kind never changes:

- **Web app with a backend.** Its server keeps a client secret, and uses it to
  exchange codes and refresh tokens.
- **Browser or native app.** A single-page, mobile or desktop app can't hide a
  secret, so it proves each exchange with PKCE alone.

Both kinds use PKCE (S256).

## Redirect URIs

A redirect URI is the page of your app that auth sends the user back to, with the
code. Auth matches it exactly, so register every one your app uses. It uses HTTPS,
or HTTP on a loopback IP for a native app.

An app can also register post-logout URIs: pages auth may send the user back to
after they sign out.

## Scopes

Scopes say what your app asks to receive about the user:

| Scope | What the app receives |
| --- | --- |
| `openid` | Sign-in itself: an ID token naming the user by a stable account ID, `sub`. The SDKs always request it |
| `profile` | The user's handle (`preferred_username`), display name (`name`), profile picture URL (`picture`) and `profile_version`, which changes whenever these do |
| `email` | The account's primary email address (`email`, with `email_verified`). An account without one has no `email` claim |
| `offline_access` | A refresh token, if the app is allowed refresh tokens |

Apps registered in the developer console can request only these four. An API's own
scopes, such as `notes:read`, are registered by piquel.fr's operators for the
clients they manage.

## Tokens

A sign-in gives your app up to three tokens:

- **The ID token** says who signed in, and how: with which scopes' claims, `acr`,
  `amr` and `auth_time`. Your app validates it once, at sign-in. It expires after
  five minutes.
- **The access token** is what your app sends to an API, as
  `Authorization: Bearer <token>`. It is a signed JWT, and it expires after five
  minutes. Its `aud` names the API it is for: for an app registered in the
  console, that is the app's own client ID.
- **The refresh token** gets new access tokens without sending the user back to
  auth. It comes only with `offline_access`, for an app allowed refresh tokens. It
  works until the user's session at auth ends, 30 days after they signed in, or
  until it is revoked, as when the user signs out or removes the app's access.

A browser or native app gets a new refresh token with every refresh, and the old
one stops working. A web app with a backend keeps the same one.

## Consent

The first time a user signs in to your app, auth asks for their consent and lists
what the app will receive. Auth remembers their answer for each scope, so a new
scope asks again. Apps registered in the console are never trusted to skip that
first ask, and their consent page says they are unverified, registered by your
handle.

Users can remove an app's access under **Connected apps** in their settings. The
app then asks for consent again at its next sign-in.

## Choose an SDK

| Your app | Use |
| --- | --- |
| A server built with axum | The Rust SDK, `piquel-auth`: [signing in with Rust](sign-in-rust.md) |
| A server that answers standard `Request`s with `Response`s: Node, Bun, Cloudflare Workers, Hono, SvelteKit | `@piquel/auth/server`: [signing in with TypeScript](sign-in-typescript.md) |
| A page with no server | `@piquel/auth/browser`: [browser apps](browser-apps.md) |
| An API that accepts access tokens | Either SDK: [protecting an API](protect-an-api.md) |
| Anything else, such as a mobile app | Any OpenID Connect library, with the issuer `https://auth.piquel.fr` |

The server SDKs need a web app with a backend. A browser app is a browser or
native app.
