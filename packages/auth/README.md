# @piquel/auth

The TypeScript SDK for [auth.piquel.fr](https://auth.piquel.fr). It is ESM only and
has no runtime dependencies: it uses `fetch` and WebCrypto, so it runs in browsers,
Node 22+, Bun and Cloudflare Workers. It follows the
[SDK design](../../docs/architecture/sdk.md) and passes the shared
[test vectors](../../tests/sdk-vectors/README.md), as the Rust SDK does.

## Resource servers

Discover the issuer once, declare the API's scopes, then validate each request's
bearer token:

```ts
import { AuthError, Issuer, defineScopes } from '@piquel/auth';

const issuer = await Issuer.discover('https://auth.piquel.fr');
const notes = defineScopes('notes:read', 'notes:write');
const api = issuer.resource({ identifier: 'notes-api', scopes: notes });

export async function handle(request: Request): Promise<Response> {
  try {
    // Requires notes:write, which a request without a token is told; 'notes:delete'
    // would not compile.
    const token = await api.authenticate(request, 'notes:write');
    token.requireAuthentication({ acr_values: 'phr', max_age: 300 });
    return Response.json({ user: token.subject.id });
  } catch (error) {
    if (error instanceof AuthError) return error.toResponse();
    throw error;
  }
}
```

- `Issuer.discover` requires the document's `issuer` to equal the URL exactly, `S256`
  PKCE and `https` endpoints.
- `authenticate` reads `Authorization: Bearer` only, and `validate` takes a token.
  Both run every check of the SDK design in order, with a 30-second leeway on times.
  `authenticate` also requires the scopes it is given, and names them in the
  challenge to a request without a token.
- `require` narrows the token's type to the scopes it proves, so a function can ask
  for `AccessToken<Notes, 'notes:write'>`. `has` checks without throwing.
- `requireAuthentication` checks a `StepUpRequirement`: `phr` meets every class, and
  `max_age` needs `auth_time`.
- `token.subject` is `{ kind: 'user', id }`, or `{ kind: 'client', id }` for a client
  acting for itself; `token.claims` holds every validated claim.
- A resource's `claims` option reads the application's own claims, which auth does
  not define, into `token.extra`, typed by what it returns:
  `claims: (claims) => ({ tenant: String(claims.tenant) })`. It runs with the claims
  check, so throwing fails the token with `invalid_claims`.

Every failure is an `AuthError` with a `code` (the category) and a `reason` (the check
that failed). `toResponse()` answers with the status and the canonical
`WWW-Authenticate` challenge, or 503 when signing keys cannot be fetched.
`parseChallenge` reads a challenge back, for clients stepping up.

`Issuer.discover` takes `fetch` and `clock` options, to send requests through another
client or pin time in tests.

## Signing users in

`issuer.client()` runs the authorization code flow with PKCE, `state`, `nonce` and
the RFC 9207 issuer check:

```ts
const client = issuer.client({
  clientId: 'notes-web',
  clientSecret: process.env.NOTES_CLIENT_SECRET, // none for a public client
  redirectUri: 'https://notes.example/auth/callback'
});

// 1. Send the browser to `url`. Keep `pending` server-side under its `state`:
//    it holds the PKCE verifier.
const { url, pending } = await client.authorize({ scopes: ['profile', 'offline_access'] });

// 2. On the callback, take the pending login back, once, and complete it.
const tokens = await client.complete(pending, new URL(request.url).searchParams);
tokens.idToken?.claims.sub;
```

- `authorize` pushes the request (RFC 9126) whenever the issuer advertises it, so
  the browser carries only a `request_uri`, as clients registered with
  `--require-par` need. A `stepUp` requirement, such as one `parseChallenge` read
  back, is sent as `acr_values` and `max_age`, and `complete` fails unless the ID
  token meets it. An `idTokenHint`, the signed-in user's ID token, is sent as
  `id_token_hint`, so auth signs in that account only, and `complete` fails unless
  the new ID token names the same user (`subject_mismatch`), revoking the refused
  grant.
- `complete` checks `state`, `iss`, `error` and `code` before the code goes
  anywhere, then validates the ID token against the pending login.
- `refresh`, `revoke`, `userinfo` and `logoutUrl` cover the rest of a session, and
  `logoutToken` validates a back-channel logout token auth posted. `refresh` and
  `userinfo` take the claims of the sign-in's ID token: a refreshed ID token must
  keep its `sub` (`subject_mismatch`), `auth_time` and `acr`, with no `nonce` but its
  own (`authentication_changed`, OIDC Core §12.2), and `UserInfo` must name its
  `sub` (`subject_mismatch`).

A confidential client authenticates with HTTP Basic, and a public one sends its
`client_id`.

## Server-side login

`@piquel/auth/server` is the recommended way to sign users in: tokens stay out of
scripts' reach, in a cookie sealed with the app's `CookieKey`, so the app stores
nothing. It takes a standard `Request` and returns a `Response`, so it runs as is in
Node, Bun, Workers, Hono or SvelteKit. [`examples/server.ts`](examples/server.ts) is
a whole app on Node's `http` server.

```ts
import { CookieKey, Login } from '@piquel/auth/server';

const login = new Login(
  issuer.client({ clientId, clientSecret, redirectUri: 'https://notes.example/auth/callback' }),
  // `openssl rand -base64 32`, the same on every replica, kept like the client secret.
  { cookieKey: CookieKey.fromBase64(process.env.NOTES_COOKIE_KEY ?? ''), scopes: ['profile'] }
);

export async function fetch(request: Request): Promise<Response> {
  const routed = await login.handle(request); // the routes under /auth; null otherwise
  if (routed) return routed;
  const user = await login.session(request); // null, the signed-in user, or a response
  if (user instanceof Response) return user; // 403 from another site, or 503
  // `respond` adds the cookies the read needs, such as the refreshed session.
  if (!user) return login.respond(request, login.signIn(request)); // through login and back, or 401
  const stepUp = user.require({ acr_values: 'phr', max_age: 300 });
  if (stepUp) return login.respond(request, stepUp); // a recent passkey sign-in
  return login.respond(request, new Response(`Hello ${user.name}`)); // await user.accessToken() calls APIs
}
```

- **Routes**, under `mount` (`/auth` by default): `GET /login?return_to=/page`,
  `GET /callback` and `POST /logout`. Register `<app>/auth/callback` as the redirect
  URI. `return_to` must be a same-origin path, and logout accepts only posts from the
  app's own pages (`Sec-Fetch-Site`, else `Origin`). Every answer has
  `Cache-Control: no-store`, and a failure answers 500, reported with
  `console.error`.
- **Confidential clients only**: `new Login` throws a `TypeError` for a client without
  a secret. Every login requests `offline_access`, which the client's registration
  must allow: auth does not rotate a confidential client's refresh token, so every
  copy of the cookie refreshes safely.
- **Sessions** live in the `__Host-piquel-<client_id>-session` cookie (`Secure`,
  `HttpOnly`, `SameSite=Lax`), sealed with AES-256-GCM, for `sessionLifetime` (12
  hours by default). It holds the tokens and the ID token's claims, not the ID token.
  A browser keeps up to three logins in progress, in cookie slots chosen by their
  `state`, so logins started in several tabs usually all complete; one that lands in
  a taken slot replaces the login there. `session()` refreshes an access token about to expire, and concurrent
  requests may each refresh. Auth's `invalid_grant` ends the session, so one auth
  ended stops within an access token's 5 minutes, as does a refreshed ID token
  naming another user or sign-in; any other failure keeps it while its access token
  is valid, and then answers 503 until auth answers again. A sign-in without a
  refresh token lasts as long as its access token.
- **`respond`** adds what `session()` recorded: the refreshed session, an ended
  session's deletion, and the spent step-up marker, with `Cache-Control: no-store`
  when it sets the session. A response without them loses those updates: the next
  request refreshes again, a dead cookie is sent until it expires, and the marker
  lingers for its minute.
- **Redirects**: `signIn` and `stepUp` redirect only a browser navigating to a page
  (`GET` with `Sec-Fetch-Mode: navigate`). Any other request, a `fetch` or a client
  sending no fetch metadata, gets 401, since a `fetch` following a redirect to auth
  would fail its CORS check; a script handles it, for example by sending the browser
  to `/auth/login`.
- **Logout** revokes the session's refresh token at auth, clears the cookies and
  redirects to RP-initiated logout. When auth cannot revoke it within five seconds,
  logout answers 502 and keeps the cookie, for the user to try again. A sign-in
  revokes the session it replaces once its code is redeemed, and answers 502 the
  same way; the code is spent then, so its new grant is revoked too.
- **Cross-site writes**: `SameSite=Lax` keeps the cookie off other sites' posts, but
  not off a sibling's under the same domain. So `session()` answers a request that is
  not `GET`, `HEAD`, `OPTIONS` or `TRACE` with a 403 response, before reading the
  session and with or without a cookie, unless it comes from the app's own pages, by
  logout's rule. Handlers need no CSRF token. An endpoint that other origins call
  with the cookie, such as a sibling site's `fetch` with credentials under CORS, opts
  out with `login.session(request, { crossOrigin: true })`, and guards against
  cross-site request forgery itself.
- **Back-channel logout**, for an app that must end sessions sooner than their next
  refresh: `backchannelLogout: async (token) => …` mounts
  `POST /backchannel-logout`, to register as the client's back-channel logout URI.
  The route validates the token and hands it to the handler, which records it where
  every replica sees it; the app then refuses sessions with the token's `sid`
  (`user.sid`), or for a token naming only the user, every session of `user.sub`
  signed in (`auth_time`) before the token's `iat`. A record can go after a session
  lifetime. Auth delivers again until it gets a 200, so the handler must be idempotent
  and resolve only once its record is durable; a rejection answers 500.
- **Step-up**: `user.require(requirement)` and `user.stepUp(challenge)`, for an API's
  `insufficient_user_authentication` challenge read with `parseChallenge`, redirect
  through login with `acr_values` and `max_age`, back to the same page. That return
  is the retry: asked again, they answer 403 instead of another redirect. A step-up
  must sign in the session's user: one that comes back as another account, or
  beside another account's session, fails with 400, keeping the session and
  revoking the refused grant.

The `CookieKey` must be the same on every replica; changing it signs every user out.
`CookieKey.generate()` makes a random one, for development and tests.

## Browser apps

`@piquel/auth/browser` signs users in to a page with no server, as a public client.
Tokens live in the page's memory only:

```ts
import { Issuer } from '@piquel/auth';
import { browserClient } from '@piquel/auth/browser';

const issuer = await Issuer.discover('https://auth.piquel.fr');
const auth = browserClient(issuer, {
  clientId: 'notes-web',
  redirectUri: `${location.origin}/callback`
});

// On every page load: finish a callback, or restore the session with prompt=none.
let session = (await auth.handleCallback()) ?? (await auth.restore({ scopes: ['profile'] }));
// On the user's click: a passkey on this page, or auth's pages with auth.login().
session ??= await auth.signInWithPasskey({ scopes: ['profile'] });
const notes = await session.fetch('https://notes.example/notes');
```

- `login` and `restore` send the browser to auth. Only the pending login (PKCE
  verifier, `state`, `nonce`, issuer) crosses the redirect, in `sessionStorage`,
  and `handleCallback` deletes it before completing, then puts the page the login
  left from back in the address bar. No token is ever written to `localStorage`,
  `sessionStorage` or a cookie.
- `restore` asks with `prompt=none`. When auth has no session it can use silently,
  `handleCallback` returns `null`, and `restore` does not try again on that page
  load, nor after a callback that found no login waiting, so a signed-out user does
  not loop. A restore after a step-up that failed keeps that step-up's retry spent,
  so a page whose request asked for it does not ask again within a minute of that
  restore's return.
- `signInWithPasskey` signs in on the page itself, through WebAuthn related
  origins, for a trusted client whose origin auth approved (see auth's README,
  "Passkey sign-in on an application's own pages"). When it needs auth's pages, it
  sends the browser there with the pushed request: the same one when auth left it
  unclaimed (the browser lacks related origins, or start answered
  `interaction_required`), and a fresh one after any other failure, since auth may
  have claimed it. `authorizeWithPasskey(issuer, requestUri)` runs the ceremony
  alone, a `request_uri` in and `{ code, state, iss }` out, throwing a
  `PasskeyError` that says whether the request is still unclaimed.
- `session.fetch` sends the access token, refreshed shortly before it expires when
  the login was granted `offline_access`; without a refresh token, an expired one
  throws `invalid_token` (`expired`), and `restore` signs in again. A resource
  answering `insufficient_user_authentication` sends the browser to auth with the
  challenge's `acr_values` and `max_age` and the ID token as `id_token_hint`, back to
  the same page, where a sign-in as another account fails; if the resource
  still refuses within a minute of that return, `fetch` throws instead of leaving
  again. A router's `load` runs before the address changes, so it passes the page it
  loads: `session.fetch(resource, init, { returnTo })`. A cross-origin resource must
  expose `WWW-Authenticate` (`Access-Control-Expose-Headers`).
- `session.claims` holds the user's ID token claims, and `session.logout()` revokes
  the refresh token and runs RP-initiated logout.

A passkey sign-in on the page leaves no session cookie at auth, so after a reload
`restore` cannot find it, and the user confirms their passkey again. DPoP-bound
refresh tokens (#214), kept in IndexedDB under a non-extractable key, will let a
session survive reloads without a redirect.

## Other JWKS issuers

`KeyCache` verifies JWS signatures against any JWKS URL, refetching once on an unknown
key ID and at most every 30 seconds:

```ts
import { Jws, KeyCache } from '@piquel/auth';

const keys = new KeyCache('https://www.googleapis.com/oauth2/v3/certs');
const jws = Jws.parse(token);
await keys.verify(jws, jws.requireAlgorithm(['RS256']));
const claims: unknown = JSON.parse(new TextDecoder().decode(jws.payload));
```

To pin keys, or verify with no network, parse a key set and give it to
`KeyCache.fixed`, which never fetches, so a key ID the set lacks fails with
`unknown_key`. `KeySet.parse` takes the JSON text or the parsed document, skips keys
it cannot use (an unknown `kty` or `alg`, a `use` other than `sig`) and throws a
`keys` error on two keys with one `kid`:

```ts
import { readFile } from 'node:fs/promises';
import { KeyCache, KeySet } from '@piquel/auth';

const keys = KeyCache.fixed(KeySet.parse(await readFile('jwks.json', 'utf8')));
```

## Development

`src/protocol.ts` is generated from the Rust wire types by `just sdk-types`; do not
edit it. `just web test` runs the unit tests and every shared vector with Node's test
runner on the TypeScript sources, and `just web smoke` validates a vector token with
the built package in Node, Bun and workerd.
