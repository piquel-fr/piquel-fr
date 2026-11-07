# Signing in with TypeScript

`@piquel/auth/server` signs users in to a server-side app. It serves the login
routes, keeps each user's session in a sealed cookie, and gives your code the
signed-in user. It takes a standard `Request` and returns a `Response`, so it runs
in Node, Bun, Cloudflare Workers, Hono, SvelteKit and the like. Your app stores
nothing.

The code on this page comes from the SDK's example app,
[`examples/server.ts`](https://github.com/piquel-fr/piquel-fr/blob/main/packages/auth/examples/server.ts),
which runs on Node's `http` server.

## Before you start

1. [Register](register-an-app.md) a **Web app with a backend**. `new Login` throws
   a `TypeError` for a browser or native app.
2. In its settings, add the redirect URI `https://<your app>/auth/callback`.
   Every login requests `offline_access`, so the session can refresh its access
   token: tick the `offline_access` scope, or sign-in fails, and **Allow refresh
   tokens**, or each session lasts only as long as its first access token, five
   minutes.
3. Generate a cookie key, which seals the session cookies:

   ```console
   openssl rand -base64 32
   ```

   Keep it secret, like the client secret, and give every replica the same one.
   Changing it signs every user out. `CookieKey.generate()` makes a random one,
   for development and tests.
4. Add `@piquel/auth` to your app. It is not on npm yet: build it from a checkout
   of the repository, then install it from there.

   ```console
   pnpm install --frozen-lockfile
   pnpm --filter @piquel/auth build
   npm install <checkout>/packages/auth
   ```

   The first two commands run in the checkout, and the last in your app.

## Sign users in

Discover the issuer, then make a `Login` from your app's registration and the
cookie key:

```ts
import { Issuer } from '@piquel/auth';
import { CookieKey, Login, type SignedIn } from '@piquel/auth/server';

{{#include ../../../packages/auth/examples/server.ts:login}}
```

`scopes` lists what to request besides `openid` and `offline_access`, which every
login requests. `backchannelLogout` is optional: see
[End sessions auth ended](#end-sessions-auth-ended).

Then answer each request: the login routes first, then your own pages with the
session. The snippets come from
[the full example](https://github.com/piquel-fr/piquel-fr/blob/main/packages/auth/examples/server.ts),
which also defines the small helpers they call, `env`, `page` and `escape`.

```ts
{{#include ../../../packages/auth/examples/server.ts:handle}}
```

`login.handle` answers the login routes and returns `null` for any other request:

- `GET /auth/login?return_to=/page` sends the browser to auth, and back to
  `/page` once signed in. `return_to` must be a path on your app.
- `GET /auth/callback` completes the sign-in and sets the session cookie.
- `POST /auth/logout` signs the user out.

The `mount` option moves the routes from `/auth`, and `afterLogin` sets where a
sign-in lands when it came from no page, `/` by default. `Issuer.discover` takes
`fetch` and `clock` options, to send its requests through another client or pin
time in tests.

The session lives in the `__Host-piquel-<client ID>-session` cookie, which is
`Secure`, `HttpOnly` and `SameSite=Lax`, so scripts can't read its tokens. It
lasts 12 hours, or what the `sessionLifetime` option says, in milliseconds. It
ends sooner when auth refuses its refresh token, such as after the user signs out
at auth. A browser can have three sign-ins in progress at once, such as in several
tabs.

## Read the signed-in user

`login.session(request)` returns the signed-in user, `null`, or a response to send
as is: a `403` or a `503`, described below. It refreshes the access token first
when it is about to expire.

Pass every response through `login.respond(request, response)`. It adds the
cookies the session's read needs, such as the refreshed session. Without them, the
next request refreshes again.

`login.signIn(request)` sends a browser that opens a page signed out through login
and back to it. Any other request, a `fetch` included, gets `401`.

`SignedIn` holds the user's `name`, `picture`, `sub`, `sid` and the ID token's
`claims`. `await user.accessToken()` is the access token, for calling an API as
the user.

Requests other than `GET`, `HEAD`, `OPTIONS` and `TRACE` must come from your app's
own pages, or `session` answers `403`, so your handlers need no CSRF token. An
endpoint other sites call with the session cookie reads it with
`login.session(request, { crossOrigin: true })`, and guards against cross-site
request forgery itself.

## Sign users out

Post a form to the logout route from one of your pages:

```html
<form method="post" action="/auth/logout"><button>Sign out</button></form>
```

The route revokes the session's refresh token, clears the cookies and sends the
browser to auth, which asks **Ready to sign out?**. **Sign out** also ends the
user's piquel.fr session in that browser, and **Keep my session** keeps it. Auth
then sends the browser to the `afterLogout` URL, which must be one of the app's
post-logout URIs. Without one, auth shows its own page.

## End sessions auth ended

A session learns that auth ended it at its next refresh, within five minutes. An
app that must stop sooner handles [back-channel logout](back-channel-logout.md)
with the `backchannelLogout` option, as the example does. It mounts
`POST /auth/backchannel-logout`, which validates auth's logout token and hands it
to your function.

The SDK keeps no sessions, so your function records the session that ended, and
your app refuses it, as `handle` does above with `user.sid`. Keep the record where
every replica sees it, such as your database. Auth may deliver a logout twice, so
the function must accept a repeat, and resolve only once the record is saved. Then
register `https://<your app>/auth/backchannel-logout` as the app's **Back-channel
logout URI**.

## Ask for a recent passkey

`user.require(requirement)` returns `null` when the sign-in meets the requirement,
or the response that signs the user in again, as the example's `/settings` page
does. When an API you call answers with an `insufficient_user_authentication`
challenge, read its `WWW-Authenticate` header with `parseChallenge` from
`@piquel/auth`, and return `user.stepUp(challenge)`.

Either way, the browser goes through login and comes back to the same page, which
tries again. If the page asks again on that return, the answer is `403` rather than
another sign-in. A step-up that signs in another account fails with `400`, and
keeps the session. [Step-up authentication](step-up.md) explains how to choose the
requirement.

## Run the sign-in yourself

`Login` covers most server-side apps. For anything else, `issuer.client()` runs
the authorization code flow, with PKCE, `state`, `nonce` and the issuer check, for
either kind of app:

```ts
const client = issuer.client({
  clientId: 'notes-web',
  clientSecret: process.env.CLIENT_SECRET, // none for a browser or native app
  redirectUri: 'https://notes.example/auth/callback'
});

// 1. Send the browser to `url`. Keep `pending` server-side under its `state`:
//    it holds the PKCE verifier.
const { url, pending } = await client.authorize({ scopes: ['profile', 'offline_access'] });

// 2. On the callback, take the pending login back, once, and complete it.
const tokens = await client.complete(pending, new URL(request.url).searchParams);
```

`authorize` takes a `stepUp` requirement, and an `idTokenHint`, the signed-in
user's ID token, so auth signs in that user only. `complete` checks the callback
before the code goes anywhere, then validates the ID token. `refresh`, `revoke`,
`userinfo` and `logoutUrl` cover the rest of a session, and `logoutToken` validates
a back-channel logout token.

## Check that it works

1. Open a page that needs a user. The browser goes to auth's sign-in page, then
   the first time to its consent page.
2. Sign in. The browser comes back to the page, which shows you signed in.
3. Sign out with the logout form, and confirm with **Sign out** at auth. Opening
   the page again asks you to sign in again.

## Troubleshooting

- **`new Login` throws a `TypeError`:** the client has no secret. Register a web
  app with a backend.
- **Sign-in answers `502`, "Sign-in could not start":** auth refused the
  sign-in request, and the message says why, such as a scope the app may not
  request: `offline_access` when its scope is left unticked.
- **Sign-in answers `400`, "This sign-in has no pending login":** the browser lost
  the login's cookie, or opened the callback twice. Start again from
  `/auth/login`.
- **Every user is signed out after a deploy:** the replicas use different cookie
  keys, or the key changed.
- **A page answers `503`:** the access token expired and auth could not renew it.
  The session is kept, and the next request tries again.
- **Sign-out answers `502`:** auth could not revoke the session's refresh token
  within five seconds. The session is kept, so the user can try again.
- **A login route answers `500`:** it failed, and logged why with
  `console.error`.
