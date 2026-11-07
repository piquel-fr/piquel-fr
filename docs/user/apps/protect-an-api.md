# Protecting an API

An API protected by piquel.fr accepts the access tokens auth issues, and checks
on each request that the token is valid and grants what the request needs. Both
SDKs do this for you, with the API's scopes declared as types, so a misspelled
scope doesn't compile.

The code on this page comes from the SDKs' examples,
[`examples/notes.rs`](https://github.com/piquel-fr/piquel-fr/blob/main/crates/auth-sdk/examples/notes.rs)
and
[`examples/resource.ts`](https://github.com/piquel-fr/piquel-fr/blob/main/packages/auth/examples/resource.ts).

## Before you start

- Know which tokens your API accepts: those whose `aud` is its identifier. For an
  app registered in the console, that is the app's client ID, so an API that
  serves your own app uses your app's client ID as its identifier. The examples
  below use `notes-api`, which stands for an audience an operator registered for
  a first-party API. [How sign-in works](how-sign-in-works.md#tokens) explains the
  tokens.
- Add an SDK to your API, as [signing in with Rust](sign-in-rust.md#before-you-start)
  or [with TypeScript](sign-in-typescript.md#before-you-start) shows. The Rust
  layer and extractors below need its `axum` feature.

## Validate tokens

Each request sends its access token as `Authorization: Bearer <token>`. The SDKs
read it from that header only. They check the token's signature against auth's
keys, its issuer, its `aud` and its times, with 30 seconds of leeway for clock
skew.

### Rust

Declare the API's scopes once with `scopes!`:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:scopes}}
```

Add a `BearerLayer` for the API's identifier, the `aud` its tokens carry:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:issuer}}
{{#include ../../../crates/auth-sdk/examples/notes.rs:api}}
```

Then take what each handler needs:

```rust
{{#include ../../../crates/auth-sdk/examples/notes.rs:handlers}}
```

- `Scoped<S>` requires the scopes `S`, one or a tuple of them. A request without a
  token gets `401`, naming the scopes, and a token without them gets `403`
  `insufficient_scope`.
- `Authenticated` requires a valid token, and nothing more.
- Each holds the validated `AccessToken`. Its `subject()` is the user it acts for,
  `Subject::User`, or `Subject::Client` for an app acting for itself.

A request without a token passes through the layer, so public routes can share
the router: only the extractors refuse it. Outside axum, `ResourceValidator`
validates a token string with `validate::<S>(token)`.

### TypeScript

Declare the API's scopes with `defineScopes`, and make a resource for the API's
identifier, the `aud` its tokens carry:

```ts
import { AuthError, Issuer, defineScopes } from '@piquel/auth';

{{#include ../../../packages/auth/examples/resource.ts:resource}}
```

Then authenticate each request:

```ts
{{#include ../../../packages/auth/examples/resource.ts:handle}}
```

- `authenticate(request, ...scopes)` validates the request's token and requires
  the scopes. A request without a token is refused, naming the scopes.
  `validate(token)` validates a token string.
- `token.require(...scopes)` requires more scopes later, and `token.has(scope)`
  checks one without throwing. A scope you didn't declare doesn't compile.
- `token.subject` is `{ kind: 'user', id }`, or `{ kind: 'client', id }` for an
  app acting for itself.
- Every failure is an `AuthError`. `toResponse()` answers with its status and
  `WWW-Authenticate` challenge.

## Scopes

Besides `openid`, `profile`, `email` and `offline_access`, an API's own scopes,
such as `notes:read`, are granted only to clients piquel.fr's operators register
with them. Apps registered in the developer console can't request them, so an API
that serves those apps checks the user, not a scope: take `Authenticated` in
Rust, and `authenticate(request)` without scopes in TypeScript.

## Ask for a recent passkey

An operation that needs a stronger or more recent sign-in checks the token's
authentication, and answers with a step-up challenge when it falls short. The
TypeScript example does this with `requireAuthentication`. In Rust, the
`RequireAuthentication<P>` extractor does it for a policy `P`.
[Step-up authentication](step-up.md) explains how to choose the requirement and
how clients answer the challenge.

## Read your own claims

A resource can also read claims that auth doesn't define, such as a tenant, from
the tokens it validates:

- In Rust, `issuer.resource(...).with_claims::<X>()` deserializes them into `X`,
  which the token holds as `extra()`.
- In TypeScript, the resource's `claims` option reads them into `token.extra`:
  `claims: (claims) => ({ tenant: String(claims.tenant) })`. Throwing fails the
  token with `invalid_claims`.

## Verify tokens from another issuer

`KeyCache` verifies JSON Web Signatures against any JWKS URL, such as Google's.
It fetches the keys again once for an unknown key ID, and at most every 30
seconds:

```ts
import { Jws, KeyCache } from '@piquel/auth';

const keys = new KeyCache('https://www.googleapis.com/oauth2/v3/certs');
const jws = Jws.parse(token);
await keys.verify(jws, jws.requireAlgorithm(['RS256']));
const claims: unknown = JSON.parse(new TextDecoder().decode(jws.payload));
```

In Rust, `KeyCache::new(jwks_uri, http)` and `Jws` do the same. To pin keys, or
verify without the network, give a parsed `KeySet` to `KeyCache.fixed` in
TypeScript, or `KeyCache::fixed` in Rust: it never fetches, so a key ID the set
lacks fails with `unknown_key`.

## Check that it works

1. Call the API without a token. It answers `401`, with a `WWW-Authenticate`
   header that names the scopes the route needs, if it needs any.
2. Call it with an access token from a signed-in app, as
   `Authorization: Bearer <token>`. It answers.
3. Call it with a token lacking a scope. It answers `403`, with
   `error="insufficient_scope"`.

## Troubleshooting

- **Every token is refused with `invalid_token`:** check the identifier. It must
  equal the token's `aud` exactly: your app's client ID, for an app registered in
  the console.
- **The API answers `503`:** it could not fetch auth's signing keys. It answers
  again once auth is reachable.
- **A Rust handler answers `500`:** the route is missing `BearerLayer`.
