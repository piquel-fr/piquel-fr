# SDK design

Applications integrate with auth.piquel.fr through two public SDKs, one for Rust and
one for TypeScript. Both follow this document, and both pass the shared vectors in
[`tests/sdk-vectors`](../../tests/sdk-vectors/README.md), so a token or challenge one
SDK accepts is accepted by the other.

| Path | Package | Published | Role |
| --- | --- | --- | --- |
| `crates/auth-protocol` | `piquel-auth-protocol` | yes | Wire types shared by auth and the Rust SDK |
| `crates/auth-sdk` | `piquel-auth` | yes | Rust SDK; the `axum` feature adds the axum integration |
| `packages/auth` | `@piquel/auth` | yes | TypeScript SDK; `@piquel/auth/sveltekit` for SvelteKit |
| `packages/auth-sdk` | `@piquel/auth-sdk` | no | First-party frontend package for auth-web and piquel-web |
| `tests/sdk-vectors` | none | no | Shared test vectors |

## Wire types

The wire format is defined by types in `piquel-auth-protocol`, not by prose:

- `claims`: `AccessTokenClaims`, `IdTokenClaims`, `UserInfo`, and the parts they
  share (`AuthenticationClaims`, `ProfileClaims`, `Audience`, `Actor`,
  `Confirmation`, `Amr`, `Acr`).
- `metadata::ServerMetadata`, the discovery document.
- `step_up::StepUpRequirement`, what an operation needs from the user's
  authentication.
- `jwt`: `typ` values, claim names, and `Jwk` and `JwkSet`.
- `oauth`: grant, response and scope vocabulary, `Scopes`, `ErrorCode` and
  `ErrorResponse`.
- `challenge::BearerChallenge`, the `WWW-Authenticate` value.
- `sdk`: the error codes below.

Auth issues tokens and documents by serializing these types, and the Rust SDK
deserializes them, so the two cannot disagree. The TypeScript SDK mirrors them and
is held to them by the vectors.

## Configuration

An SDK is configured with an issuer URL. Everything else comes from discovery at
`/.well-known/openid-configuration`, and the returned `issuer` must equal the
configured one exactly: no normalization, so a trailing slash is a mismatch. The
issuer must advertise `S256` in `code_challenge_methods_supported`, and every
endpoint must use `https`; a document breaking either is refused. Advertised values an SDK does not know are dropped from their
lists rather than failing discovery, so auth can add capabilities without breaking
older SDKs.

- A **client** adds its `client_id`, its credentials (none for a public client, a
  secret for a confidential one) and its `redirect_uri`.
- A **resource** adds its identifier, which is the `aud` it accepts, and the scopes
  it understands.

The SDKs take an injectable clock, so tests and the vectors can pin time, and an
injectable HTTP client.

## Token validation

Checks run in this order, and the first failure is reported. Each failure is an
`invalid_token` error with the reason in parentheses.

1. The token is a compact JWS of three base64url segments, at most 16 KiB, with a
   JSON header (`malformed`).
2. The header has no `crit`: the SDKs understand no JWS extensions, so a critical one
   must be refused (RFC 7515 §4.1.11) (`unsupported_critical_header`).
3. `typ` is `at+jwt` for access tokens (RFC 9068) or `JWT` for ID tokens, as auth
   issues them, compared case-insensitively with or without the `application/`
   prefix (`wrong_type`).
4. `alg` is both advertised by the issuer and in the SDK's allowlist. The allowlist
   is `RS256` today; `none` and HMAC algorithms are never accepted
   (`unsupported_algorithm`).
5. `kid` names a known key, after at most one refetch (`unknown_key`).
6. The signature verifies (`bad_signature`).
7. The claims parse as the shared claim type, so required claims are present and
   well typed (`invalid_claims`).
8. `iss` equals the issuer exactly (`issuer_mismatch`).
9. `aud` contains the expected value: the resource for access tokens, the client
   for ID tokens. An ID token's `aud` must name no other client, since the SDKs
   trust no other audience (OIDC Core §3.1.3.7) (`wrong_audience`).
10. Time, with a 30-second leeway, matching auth's own `iat` skew:
   - expired when `now >= exp + 30` (`expired`);
   - not yet valid when `nbf > now + 30`, for both token types (`not_yet_valid`);
   - issued in the future when `iat > now + 30` (`issued_in_future`).
11. ID tokens only:
    - `nonce` equals the pending login's (`nonce_mismatch`);
    - `azp`, when present, is this client (`wrong_authorized_party`);
    - when the login sent `max_age`, `auth_time` must be present and
      `now <= auth_time + max_age + 30` (`authentication_too_old`).

Scope and step-up requirements are checked after validation, and fail with their
own categories.

## Signing keys

The SDKs cache the issuer's key set:

- On an unknown `kid`, refetch once, then fail with `unknown_key` if the key is
  still missing.
- Fetch at most once every 30 seconds, whatever the reason. A token with another
  unknown `kid` inside that window fails without a request, so unknown key IDs
  cannot be used to flood the issuer.
- Keys stay fresh for the response's `Cache-Control: max-age`, bounded to between
  30 seconds and 24 hours, or for one hour when there is none.
- A failed refresh keeps the last good set, and still counts as a fetch.
- Keys of an unknown `kty`, and keys whose `use` is not `sig`, are skipped (RFC 7517
  §5). A set where two keys share a `kid` is rejected as a whole, and the previous
  set stays in use.

This handles signing key rotation: auth publishes the new key before it signs with
it, so tokens from both keys verify during the overlap. The Rust key cache works
with any JWKS URL, so auth also uses it for Google.

## Scopes

Scopes are space-separated strings on the wire (RFC 6749 §3.3), and each token is
printable ASCII without spaces, `"` or `\`. Each SDK types them: Rust declares an
application's scopes once with a macro, so a required scope is a type and a
misspelled scope does not compile. TypeScript uses string literal types.

## Errors

Every SDK error has a category and, for most categories, a reason. Both SDKs expose
the same values, listed in `piquel_auth_protocol::sdk`.

| Category | Meaning | Reasons |
| --- | --- | --- |
| `discovery` | Metadata could not be used | `issuer_mismatch`, `invalid_document`, `pkce_unsupported` |
| `keys` | The key set could not be used | `invalid_document`, `duplicate_key_id` |
| `invalid_token` | A token failed validation | see [Token validation](#token-validation) |
| `insufficient_scope` | A valid token lacks a required scope | none |
| `insufficient_user_authentication` | A valid token's authentication is too weak or too old | none |
| `callback` | An authorization response failed before the code exchange | `state_mismatch`, `issuer_mismatch`, `missing_issuer`, `missing_code` |
| `oauth` | An auth endpoint answered with an OAuth error | none; the OAuth `error` is kept |
| `network` | Auth could not be reached, or answered outside its protocol | none |

On a resource server, each error maps to one `WWW-Authenticate: Bearer` challenge
(RFC 6750 §3, RFC 9470 §3):

| Situation | Status | Challenge |
| --- | --- | --- |
| No token | 401 | no `error`; `scope` and `resource_metadata` when known |
| `invalid_token` | 401 | `error="invalid_token"` |
| `insufficient_scope` | 403 | `error="insufficient_scope"` with every required scope |
| `insufficient_user_authentication` | 401 | `error="insufficient_user_authentication"` with `acr_values` and `max_age` |
| A malformed `Authorization` header | 400 | `error="invalid_request"` |

The parameters are always written in the order `error`, `error_description`,
`scope`, `acr_values`, `max_age`, `resource_metadata`, with every value quoted, so
both SDKs produce identical headers. `error_description` is printable ASCII without
`"` or `\` (RFC 6750 §3), which also keeps it from breaking the header. Parsers
follow the RFC 9110 §11 grammar: any parameter order, token or quoted values, and
other challenges in the same header, including `token68` ones. A header that breaks
the grammar, or a Bearer challenge with an invalid parameter, holds no challenge.
`resource_metadata` is added once resources publish protected resource metadata
(RFC 9728).

## Login

Login uses the authorization code flow with S256 PKCE, `state` and `nonce`:

1. `authorize` returns the authorization URL and a pending login holding the PKCE
   verifier, `state`, `nonce`, the expected issuer, the redirect URI and any step-up
   requirement it asks for with `acr_values` and `max_age`. The pending login is stored server-side and consumed by the callback,
   so a callback completes at most once.
2. The callback is checked before the code goes anywhere:
   1. `state` equals the pending login's (`state_mismatch`).
   2. RFC 9207 §2.4: when the response carries `iss`, it must equal the issuer
      (`issuer_mismatch`). When it carries none but the metadata advertises
      `authorization_response_iss_parameter_supported`, it is rejected
      (`missing_issuer`). This applies to error responses too.
   3. An `error` parameter becomes an `oauth` error.
   4. Otherwise `code` must be present (`missing_code`).
3. The code is exchanged with the verifier and redirect URI, and the ID token is
   validated against the pending login's `nonce` and `max_age`. It must also meet
   the login's step-up requirement (`insufficient_user_authentication`), so a
   step-up login that falls short fails instead of being asked for again.

The SDKs never send the `audience` parameter auth accepts today; auth then uses the
client's default resource. They will send `resource` (RFC 8707) once auth supports
it.

Browser tokens stay in memory. Server-side apps keep tokens in a server-side session
and give the browser only a random session key, in a `__Host-` cookie that is
`Secure`, `HttpOnly` and `SameSite=Lax`. Every sign-in starts a session under a
fresh key. Refresh tokens never reach the browser.

Applications choose where sessions live by implementing a small storage backend:
load, insert, a compare-and-swap replace, and a remove that reports whether the
record existed. The SDK keeps everything else: the record format and its validation,
expiry, pending logins, and the refresh lease. Backends see only opaque records under
the SHA-256 of each session key, so reading the backend does not give access to
sessions. The SDK ships an in-memory backend for development and tests, and a check
applications run against their own backend.

Auth rotates refresh tokens and revokes the whole family on reuse, so concurrent
refreshes of one session are serialized through a lease the SDK keeps in the session
record, shared by every replica through the backend's compare-and-swap. Leases
expire by wall-clock time, so replicas need synchronized clocks; a lease lasts a
minute, and its holder must refresh and save before it expires, or give it back. The lease is taken only at the session version the request read,
so a request that read the session before another refresh reloads it instead of
redeeming the rotated token. Each lease has an ID, and only its holder can save the
result, so a slow attempt cannot overwrite a later one or resurrect a logged-out
session. Once a refresh may have reached auth without its answer being saved (a
timeout, a lost response, a lease that expired unreleased), the stored token may be
spent, so the session ends and the user signs in again rather than risk a reuse
that would revoke the family. `invalid_grant` ends the session too; any other error
answer from auth keeps it. Logout accepts only requests from the app's own origin.

Back-channel logout is added to the SDKs together with auth's side (#65).

## Step-up

What an operation needs from the user's authentication is a
`step_up::StepUpRequirement`: an `acr` to meet, a maximum age of `auth_time`, or
both. Auth checks its own account APIs and authorization requests with the same
type's `check`, and the SDKs check tokens with it too:

- `acr` classes are ordered: `phr` meets every class, and
  `urn:piquel:acr:social` meets only itself. A token without `acr`, or with one the
  SDK does not know, meets no `acr` requirement.
- `max_age` needs `auth_time`, and holds while `now - 30 <= auth_time + max_age`,
  with the same leeway as the other time checks.

Auth itself applies no leeway, and at its authorize endpoint `max_age=0` means a
sign-in after the request, like `prompt=login`. So a token up to 30 seconds past a
`max_age` still passes an SDK, while auth asks for a new sign-in; the leeway only
absorbs clock skew between auth and the resource.

A resource whose requirement is not met answers with
`insufficient_user_authentication`, the requirement's `acr_values` and `max_age`
(RFC 9470). A challenge names at most one class. A client parses the challenge back
into a requirement, taking the first `acr_values` entry it knows, as auth does, and
runs authorization again with those values.

A client retries at most once per user action. It signs the user in again with the
challenge's values and returns to the same page. If the resource still refuses on
that return, the client reports the error instead of redirecting again. A server-side
client recognizes the return by a short-lived marker, so a much later return counts
as a new action. The login check above also means a step-up sign-in never completes
below its requirement.

## Forward compatibility

Claims auth does not issue yet already have a shape, so applications can be written
against them now:

- `act` (`Actor`), nested for delegation chains (RFC 8693 §4.1).
- `cnf.jkt` (`Confirmation`), for `DPoP`-bound tokens (RFC 9449).

`acr` (`Acr`) and `amr` (`Amr`) are closed vocabularies, separate from auth's stored
`AuthenticationMethod`, so new values need a new SDK version to be read. Until then
they do not fail the token: an `amr` value the SDK does not know is dropped, and an
unknown `acr` reads as none, which meets no requirement. Discovery lists drop unknown
values the same way.

OAuth error codes and Bearer `error` codes are open instead, since their registries
keep growing: a code a parser does not know becomes an "other" variant holding the
string, so it still yields the rest of the error body or challenge.

## Test vectors

`tests/sdk-vectors` holds one JSON file per case: inputs, a fixed `now`, and either
the parsed value or the expected error code. The generator,
`crates/auth-protocol/tests/sdk_vectors.rs`, builds them from fixed test keys and the
shared claim types and signs them with auth's signer. `just sdk-vectors` rewrites
them, and `just test`, and so `just validate`, fails when they are stale. Both SDK
test suites run every case.
