# Signing in with Rust

The Rust SDK, `sourceorigin-auth`, signs users in to an axum app. Its `axum` feature
mounts the login routes, keeps each user's session in a sealed cookie, and hands
your handlers the signed-in user. Your app stores nothing.

The code on this page comes from the SDK's example app,
[`examples/notes.rs`](https://github.com/sourceorigin-dev/sourceorigin/blob/main/crates/auth-sdk/examples/notes.rs).

## Before you start

1. [Register](register-an-app.md) a **Web app with a backend**. The login routes
   refuse a browser or native app.
2. In its settings, add the redirect URI `https://<your app>/auth/callback`.
   Every login requests `offline_access`, so the session can refresh its access
   token: turn on the `offline_access` scope, or sign-in fails, and **Allow
   refresh tokens**, or each session lasts only as long as its first access token, five
   minutes.
3. Generate a cookie key, which seals the session cookies:

   ```console
   openssl rand -base64 32
   ```

   Any 32 random bytes work, written in base64, base64url or hex, such as a
   secret [piqueld generates](deploying-with-piqueld.md#store-the-secrets).
   Keep it secret, like the client secret, and give every replica the same one.
   Changing it signs every user out.
4. Add the SDK to your app's `Cargo.toml`:

   ```toml
   [dependencies]
   sourceorigin-auth = { git = "https://github.com/sourceorigin-dev/sourceorigin", features = ["axum"] }
   axum = "0.8"
   tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
   ```

## Sign users in

Discover the issuer, then build the login routes from your app's registration and
the cookie key:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:issuer}}
{{#include ../../../crates/auth-sdk/examples/notes.rs:login}}
```

`scopes` lists what to request besides `openid` and `offline_access`, which every
login requests. Then nest the routes at `/auth`, and add the layer around every
route that reads the session. `ended`, the sessions auth ended, is the state of
`home` below:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:router}}
```

The router serves:

- `GET /auth/login?return_to=/page` sends the browser to auth, and back to
  `/page` once signed in. `return_to` must be a path on your app.
- `GET /auth/callback` completes the sign-in and sets the session cookie.
- `POST /auth/logout` signs the user out.

To mount the routes elsewhere, nest them there and tell `LoginRoutes::mounted_at`.
`after_login` sets where a sign-in lands when it came from no page, `/` by default.

The session lives in the `__Host-sourceorigin-<client ID>-session` cookie, which is
`Secure`, `HttpOnly` and `SameSite=Lax`, so scripts can't read its tokens. It
lasts 12 hours, or what `session_lifetime` says. It ends sooner when auth refuses
its refresh token, such as after the user signs out at auth. A browser can have
three sign-ins in progress at once, such as in several tabs.

## Read the signed-in user

Take `SignedIn` in a handler that needs a user:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:home}}
```

A browser that opens the page signed out goes through login and comes back to it.
Any other request without a session, a `fetch` included, gets `401`.
`MaybeSignedIn` gives an `Option` instead, for pages that work either way.

`SignedIn` holds the user's `name()`, `picture()`, `subject()`, `sid()` and the ID
token's `claims()`. `login().access_token()` is the access token, for calling an
API as the user: the layer refreshes it before it expires.

Requests other than `GET`, `HEAD`, `OPTIONS` and `TRACE` must come from your app's
own pages, or they get `403`, so your handlers need no CSRF token. An endpoint
other sites call with the session cookie takes `CrossOrigin<SignedIn>`, and guards
against cross-site request forgery itself.

## Sign users out

Post a form to the logout route from one of your pages:

```html
<form method="post" action="/auth/logout"><button>Sign out</button></form>
```

The route revokes the session's refresh token, clears the cookie and sends the
browser to auth, which asks **Ready to sign out?**. **Sign out** also ends the
user's Origin Account session in that browser, and **Keep my session** keeps it. Auth
then sends the browser to the URL you gave `LoginRoutes::after_logout`, which must
be one of the app's post-logout URIs. Without one, auth shows its own page.

## End sessions auth ended

A session learns that auth ended it at its next refresh, within five minutes. An
app that must stop sooner handles [back-channel logout](back-channel-logout.md):

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:backchannel}}
```

The SDK keeps no sessions, so your handler records the session that ended, and
your app refuses it, as `home` does above with `user.sid()`. Keep the record where
every replica sees it, such as your database. Auth may deliver a logout twice, so
the handler must accept a repeat. Then register
`https://<your app>/auth/backchannel-logout` as the app's **Back-channel logout
URI**.

## Ask for a recent passkey

A page that needs a stronger or more recent sign-in returns the `StepUp` from
`SignedIn::require::<P>()`, for an `AuthenticationPolicy` `P` that names the
requirement. When an API you call answers with an
`insufficient_user_authentication` challenge, parse its `WWW-Authenticate` header
as a `BearerChallenge`, and return `user.step_up(challenge.step_up)`.

Either way, the browser goes through login and comes back to the same page, which
tries again. If the page asks again on that return, the answer is `403` rather than
another sign-in. A step-up that signs in another account fails with `400`, and
keeps the session. [Step-up authentication](step-up.md) explains how to choose the
requirement.

## Run the sign-in yourself

Outside axum, `Client`, from `issuer.client(config)`, runs the authorization code
flow for either kind of app. `authorize` gives the URL to send the browser to, and
a `PendingLogin` to keep server-side. `complete` checks the callback, then
validates the ID token. `refresh`, `revoke`, `userinfo` and `logout_url` cover the
rest of a session, and `logout_token` validates a back-channel logout token.

## Check that it works

1. Open a page whose handler takes `SignedIn`. The browser goes to auth's sign-in
   page, then the first time to its consent page.
2. Sign in. The browser comes back to the page, which shows you signed in.
3. Sign out with the logout form, and confirm with **Sign out** at auth. Opening
   the page again asks you to sign in again.

## Troubleshooting

- **`LoginRoutes::new` fails with `PublicClient`:** the client has no secret.
  Register a web app with a backend.
- **A handler answers `500`:** the route is missing `auth.layer()`.
- **Sign-in answers `502`, "Sign-in could not start":** auth refused the
  sign-in request, and the message says why, such as a scope the app may not
  request: `offline_access` when its scope is left off.
- **Sign-in answers `400`, "This sign-in has no pending login":** the browser lost
  the login's cookie, or opened the callback twice. Start again from
  `/auth/login`.
- **Every user is signed out after a deploy:** the replicas use different cookie
  keys, or the key changed.
- **Sign-out answers `502`:** auth could not revoke the session's refresh token
  within five seconds. The session is kept, so the user can try again.
- **A page answers `503`:** the access token expired and auth could not renew it.
  The session is kept, and the next request tries again.
