# Browser apps

`@sourceorigin/auth/browser` signs users in to a page with no server of its own. It
keeps the user's tokens in the page's memory, calls APIs with them, and can sign
the user in with a passkey on your page itself.

The code on this page comes from the SDK's example,
[`examples/browser.ts`](https://github.com/sourceorigin-dev/sourceorigin/blob/main/packages/auth/examples/browser.ts).

## Before you start

1. [Register](register-an-app.md) a **Browser or native app**.
2. Add the page that finishes sign-in as a redirect URI, such as
   `https://<your app>/callback`. Pages on its origin may then call auth's token
   endpoints from the browser.
3. To keep users signed in for longer than an access token's five minutes, tick
   the `offline_access` scope and **Allow refresh tokens**, and request
   `offline_access` when signing in.
4. Add `@sourceorigin/auth` to your app. It is not on npm yet: build it from a checkout
   of the repository, then install it from there.

   ```console
   pnpm install --frozen-lockfile
   pnpm --filter @sourceorigin/auth build
   npm install <checkout>/packages/auth
   ```

   The first two commands run in the checkout, and the last in your app.

## Sign users in

Discover the issuer, then make a browser client with your app's client ID and
redirect URI:

```ts
import { Issuer } from '@sourceorigin/auth';
import { browserClient, type Session } from '@sourceorigin/auth/browser';

{{#include ../../../packages/auth/examples/browser.ts:client}}
```

On every page load, finish a sign-in that is coming back, or restore the user's
session. Until the user is signed in, wait for them to click to sign in:

```ts
{{#include ../../../packages/auth/examples/browser.ts:load}}
```

- `handleCallback` finishes a sign-in when the page is the redirect URI with
  auth's answer, then puts the page the sign-in left from back in the address bar.
  On any other page it returns `null`.
- `restore` sends the browser to auth, which signs the user in again without
  asking anything, and back to `handleCallback`. If the user is signed out at auth,
  `handleCallback` returns `null`, and `restore` returns `null` for the rest of the
  page load, so the page doesn't loop.
- `login` sends the browser to auth's sign-in pages. `signInWithPasskey` signs in
  on your page, as described [below](#sign-in-with-a-passkey-on-your-page).

Each takes the scopes to request besides `openid`. `returnTo` sets the page of
your origin to come back to, the current one by default.

## Keep tokens in memory

The session's tokens live only in the page's memory. The SDK never writes them to
`localStorage`, `sessionStorage` or a cookie. While a sign-in is away at auth, only
the login waiting for it is kept, in `sessionStorage`, and `handleCallback`
deletes it.

So reloading the page loses the tokens, and `restore` signs the user in again
through auth. Load your page with `restore` on each load, as above, rather than
storing tokens yourself.

## Call an API

`session.fetch` calls an API with the user's access token:

```ts
{{#include ../../../packages/auth/examples/browser.ts:session}}
```

It refreshes the access token shortly before it expires, if the sign-in brought a
refresh token. Without one, it throws `invalid_token` once the token expires,
and `restore` signs the user in again.

An API on another origin must let the page read its `WWW-Authenticate` header,
with `Access-Control-Expose-Headers: WWW-Authenticate`. When it answers with a
[step-up challenge](step-up.md), `fetch` sends the browser to auth to sign in
again as the same user, and back to the page. If the API still refuses within a
minute of that return, `fetch` throws instead of leaving again. A router's `load`
runs before the address changes, so it passes the page it loads:
`session.fetch(url, init, { returnTo })`.

`session.claims` holds the ID token's claims, such as the user's `name`.
`session.logout(url)` revokes the refresh token and sends the browser to auth to
sign out, then to `url`, which must be one of the app's post-logout URIs.

## Sign in with a passkey on your page

`signInWithPasskey` signs the user in with their passkey without leaving your
page. It works for a trusted client whose page's origin an administrator approved:
see [passkey sign-in on your own pages](passkey-sign-in.md). Apps registered in
the developer console are never trusted.

When it can't sign in on the page, it sends the browser to auth's sign-in pages
instead, so the user can still sign in:

- When the browser doesn't support related origins, or auth refuses the request
  before the passkey prompt because only its own pages can answer it, such as a
  request with `prompt=consent`, the same request goes on at auth.
- After any other failure, such as the user cancelling the passkey prompt, a fresh
  request goes to auth.

To run the passkey prompt in your own flow, `authorizeWithPasskey(issuer,
requestUri)` takes a pushed request's `request_uri`, and returns the authorization
answer, `{ code, state, iss }`. When it fails, it throws a `PasskeyError`, whose
`unclaimed` says whether the same request can still go to auth.

A passkey sign-in on the page leaves no session at auth. After a reload, `restore`
finds none, so the user signs in again.

## Check that it works

1. Open your page and click to sign in. The browser comes back to the page,
   signed in.
2. Reload the page. It passes through auth and comes back signed in, without
   asking anything.
3. Sign out, and confirm with **Sign out** at auth. Reloading the page then
   leaves you signed out.

## Troubleshooting

- **`handleCallback` throws `state_mismatch`:** the page was opened with an
  authorization answer that no sign-in of this browser tab is waiting for, such as
  a callback opened in another tab.
- **`fetch` doesn't step up when the API asks:** the API is on another origin and
  doesn't expose `WWW-Authenticate`.
- **The user is signed in again on every reload:** this is how browser apps work,
  since tokens live in memory. It passes through auth without asking anything as
  long as the user is signed in there.
