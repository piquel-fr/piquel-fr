# @piquel/auth

The TypeScript SDK for [auth.piquel.fr](https://auth.piquel.fr). It is ESM only and
has no runtime dependencies: it uses `fetch` and WebCrypto, so it runs in browsers,
Node 22+, Deno, Bun and Cloudflare Workers. It follows the
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
  token meets it.
- `complete` checks `state`, `iss`, `error` and `code` before the code goes
  anywhere, then validates the ID token against the pending login.
- `refresh`, `revoke`, `userinfo` and `logoutUrl` cover the rest of a session, and
  `logoutToken` validates a back-channel logout token auth posted.

A confidential client authenticates with HTTP Basic, and a public one sends its
`client_id`.

## Server-side login

`@piquel/auth/server` is the recommended way to sign users in: tokens stay on the
server, and the browser holds only a random session key. It takes a standard
`Request` and returns a `Response`, so it runs as is in Node, Deno, Bun, Workers,
Hono or SvelteKit. [`examples/server.ts`](examples/server.ts) is a whole app on
Node's `http` server.

```ts
import { Login, MemoryBackend } from '@piquel/auth/server';

const login = new Login(
  issuer.client({ clientId, clientSecret, redirectUri: 'https://notes.example/auth/callback' }),
  { backend: new MemoryBackend(), scopes: ['profile', 'offline_access'] }
);

export async function fetch(request: Request): Promise<Response> {
  const routed = await login.handle(request); // the routes under /auth; null otherwise
  if (routed) return routed;
  const user = await login.session(request); // null, or the signed-in user
  if (!user) return login.signIn(request); // through login, and back to this page
  const stepUp = user.require({ acr_values: 'phr', max_age: 300 });
  if (stepUp) return stepUp; // a recent passkey sign-in, or through login again
  return new Response(`Hello ${user.name}`); // await user.accessToken() calls APIs
}
```

- **Routes**, under `mount` (`/auth` by default): `GET /login?return_to=/page`,
  `GET /callback`, `POST /logout` and `POST /backchannel-logout`. Register
  `<app>/auth/callback` as the redirect URI and `<app>/auth/backchannel-logout` as
  the back-channel logout URI. `return_to` must be a same-origin path, and logout
  accepts only posts from the app's own pages (`Sec-Fetch-Site`, else `Origin`). Every
  answer has `Cache-Control: no-store`, and a backend failure answers 500, reported
  with `console.error`.
- **Sessions** live under a `__Host-piquel-session` cookie (`Secure`, `HttpOnly`,
  `SameSite=Lax`), under a fresh key on every sign-in, for `sessionLifetime` (12 hours
  by default). `session()` refreshes an access token about to expire, once for every
  concurrent request and replica, through a lease in the session record; a refresh
  whose outcome is unknown, or that auth refuses with `invalid_grant`, ends the
  session.
- **Back-channel logout** ends every session started under the token's `sid`, or
  every session of its `sub`, on every replica sharing the backend. A replayed token
  changes nothing.
- **Step-up**: `user.require(requirement)` and `user.stepUp(challenge)`, for an API's
  `insufficient_user_authentication` challenge read with `parseChallenge`, redirect
  through login with `acr_values` and `max_age`, back to the same page. That return
  is the retry: asked again, they answer 403 instead of another redirect.

`MemoryBackend` loses every session on restart and is not shared between replicas.
Apps implement `SessionBackend` instead: `load`, `insert` (only where no record is),
`replace` (only at the expected version) and `remove`, over opaque records whose
keys are SHA-256 digests, so one table with a single statement per operation is
enough (the type's documentation shows PostgreSQL). Test it with
`checkBackend(backend)`, which throws on the first broken rule.

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
  challenge's `acr_values` and `max_age`, back to the same page; if the resource
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

## SvelteKit

There is no SvelteKit integration to install: `Login.handle` and `Login.session`
take SvelteKit's requests. [`examples/sveltekit`](examples/sveltekit) holds the files
below, type-checked against SvelteKit 3 and this package so they stay current.

**Server-rendered apps** (adapter-node, adapter-cloudflare, …) sign in as
confidential clients, and tokens never reach the browser. `src/hooks.server.ts`
serves the routes under `/auth` and sets `event.locals.user`:

```ts
import { Issuer } from '@piquel/auth';
import { Login, MemoryBackend } from '@piquel/auth/server';
import { AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, ORIGIN } from '$app/env/private';
import type { Handle } from '@sveltejs/kit/hooks';

const issuer = await Issuer.discover('https://auth.piquel.fr');
const login = new Login(
  issuer.client({
    clientId: AUTH_CLIENT_ID,
    clientSecret: AUTH_CLIENT_SECRET,
    redirectUri: `${ORIGIN}/auth/callback`
  }),
  // MemoryBackend is for development: implement SessionBackend to keep sessions.
  { backend: new MemoryBackend(), scopes: ['profile'] }
);

/** This app's origin, which its own form posts carry. */
const origin = new URL(ORIGIN).origin;

/** A form post from another site, which SvelteKit refuses unless vite.config.js trusts it. */
function crossSiteForm(request: Request): boolean {
  const type = request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() ?? '';
  const form = ['', 'application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];
  return (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) &&
    form.includes(type) &&
    request.headers.get('origin') !== origin
  );
}

export const handle: Handle = async ({ event, resolve }) => {
  // Back-channel logout is signed; every other cross-site form post is refused.
  if (event.url.pathname !== '/auth/backchannel-logout' && crossSiteForm(event.request)) {
    return new Response('Cross-site form submissions are forbidden.', { status: 403 });
  }
  const routed = await login.handle(event.request); // /auth/login, /callback, /logout, …
  if (routed) return routed;
  // `event.url` names the page even when the request is for its `__data.json`.
  const { method, headers } = event.request;
  const page = new Request(event.url, { method, headers });
  event.locals.user = await login.session(page);
  return resolve(event);
};
```

- `login.session` reads `event.url`, not `event.request`: on a client-side
  navigation the request is for the page's `__data.json`, and a step-up must come
  back to the page itself.
- Auth posts back-channel logout from its servers, without an `Origin` header,
  which SvelteKit's form check refuses. So
  [`vite.config.js`](examples/sveltekit/server/vite.config.js) trusts every origin
  (`csrf.trustedOrigins: ['*']`), and the hook refuses every other cross-site form
  post itself, comparing `Origin` with `ORIGIN` as SvelteKit's check would with
  `paths.origin`. `/auth/logout` checks its origin on its own.
- [`src/env.ts`](examples/sveltekit/server/src/env.ts) declares the settings the hook
  reads from `$app/env/private`, so the app does not start without them.
- [`src/app.d.ts`](examples/sveltekit/server/src/app.d.ts) types `locals.user` as
  `SignedIn | null`.
- [`src/routes/(app)/+layout.server.ts`](<examples/sveltekit/server/src/routes/(app)/+layout.server.ts>)
  sends signed-out visitors to `/auth/login?return_to=…`, back to the same page.
- [`src/routes/(app)/notes/+page.server.ts`](<examples/sveltekit/server/src/routes/(app)/notes/+page.server.ts>)
  calls an API with `await user.accessToken()`, and answers its
  `insufficient_user_authentication` challenge with `user.stepUp`, which signs the
  user in again once, back to the same page. A post to the page's form actions
  cannot leave for auth, so `stepUp` answers it 401, and the page's own load steps up
  when it opens again.

**Static apps** (adapter-static, with a `fallback` page) sign in as public clients
with `@piquel/auth/browser`, from a root
[`+layout.ts`](examples/sveltekit/static/src/routes/+layout.ts) with `ssr = false`.
Auth sends the callback to `/`, the redirect URI to register; the layout finishes
it, then redirects to the page the login left from, with or without a session, so
SvelteKit's router renders that page rather than the callback. It keeps the session
in memory for the page load, and restores it with `prompt=none` otherwise. A `load`
calling an API with `session.fetch` passes
`{ returnTo: untrack(() => url.href) }`, since it runs before the address changes,
and untracked, so it does not run again on every change of the URL. Its links must
not preload data: `data-sveltekit-preload-data="false"` on them overrides the
`hover` a new app's `app.html` sets, since even `tap` preloads on a press, and a
preload that steps up leaves for auth. Without `offline_access` there is no refresh
token: when `session.fetch` throws `invalid_token` (`expired`), the `load` signs in
again with `auth.restore({ scopes, returnTo })`.

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

## Development

`src/protocol.ts` is generated from the Rust wire types by `just sdk-types`; do not
edit it. `just web test` runs the unit tests and every shared vector with Node's test
runner on the TypeScript sources, and `just web smoke` validates a vector token with
the built package in Node, Deno, Bun and workerd.
