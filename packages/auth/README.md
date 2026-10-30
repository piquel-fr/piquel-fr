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
    const token = await api.authenticate(request);
    token.require('notes:write'); // 'notes:delete' would not compile
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
