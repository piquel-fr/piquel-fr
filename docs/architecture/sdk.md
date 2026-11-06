# SDK design

Applications integrate with auth.piquel.fr through its Rust SDK, `piquel-auth`, its
TypeScript SDK, `@piquel/auth`, or any OpenID Connect library. Both SDKs follow this
document and pass the shared vectors in
[`tests/sdk-vectors`](../../tests/sdk-vectors/README.md); an SDK in another language
would do the same, so every SDK accepts and rejects the same tokens and challenges.
The Rust SDK is the reference implementation, and the TypeScript SDK mirrors its
behavior and names.

| Path | Package | Published | Role |
| --- | --- | --- | --- |
| `crates/common` | `piquel-common` | yes | Shared types; with no features, the IDs and wire types shared by auth and the Rust SDK |
| `crates/auth-sdk` | `piquel-auth` | yes | Rust SDK; the `axum` feature adds the axum integration |
| `packages/auth` | `@piquel/auth` | not yet | TypeScript SDK, ESM only, with no runtime dependencies: `fetch` and WebCrypto, so it runs in browsers, Node, Bun and Workers; `@piquel/auth/server` is its server-side login over standard `Request` and `Response`, and `@piquel/auth/browser` its public client for apps without a server, passkey sign-in on the app's page included |
| `tests/sdk-vectors` | none | no | Shared test vectors |

## Wire types

The wire format is defined by types in `piquel_common::protocol`, not by prose.
The Rust SDK re-exports them by name as `piquel_auth::protocol`, so that list is
its contract:

- `claims`: `AccessTokenClaims`, `IdTokenClaims`, `LogoutTokenClaims`, `UserInfo`,
  and the parts they share (`AuthenticationClaims`, `ProfileClaims`, `Audience`,
  `Actor`, `Confirmation`, `Amr`, `Acr`).
- `metadata::ServerMetadata`, the discovery document.
- `step_up::StepUpRequirement`, what an operation needs from the user's
  authentication.
- `jwt`: `typ` values, claim names, and `Jwk` and `JwkSet`.
- `oauth`: grant, response and scope vocabulary, `Scopes`, `ErrorCode` and
  `ErrorResponse`.
- `challenge::BearerChallenge`, the `WWW-Authenticate` value.
- `sdk`: the error codes below.

Auth issues tokens and documents by serializing these types, and the Rust SDK
deserializes them, so the two cannot disagree. An SDK in another language mirrors
them and is held to them by the vectors. The TypeScript SDK's mirror is generated:
`piquel-common`'s tests write `packages/auth/src/protocol.ts` from these types with
ts-rs, vocabularies as unions of their spellings, and `just test` fails while it is
stale (`just sdk-types` rewrites it).

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

The SDK takes an injectable clock, so tests and the vectors can pin time, and an
injectable HTTP client: a `reqwest` client in Rust, a `fetch` in TypeScript.

## Token validation

Checks run in this order, and the first failure is reported. Each failure is an
`invalid_token` error with the reason in parentheses.

1. The token is a compact JWS of three base64url segments, at most 16 KiB, with a
   JSON header (`malformed`).
2. The header has no `crit`: the SDK understands no JWS extensions, so a critical one
   must be refused (RFC 7515 §4.1.11) (`unsupported_critical_header`).
3. `typ` is `at+jwt` for access tokens (RFC 9068), `JWT` for ID tokens or
   `logout+jwt` for logout tokens, as auth issues them, compared case-insensitively
   with or without the `application/` prefix (`wrong_type`).
4. `alg` is both advertised by the issuer and in the SDK's allowlist. The allowlist
   is `RS256` today; `none` and HMAC algorithms are never accepted
   (`unsupported_algorithm`).
5. `kid` names a known key, after at most one refetch (`unknown_key`).
6. The signature verifies (`bad_signature`).
7. The claims parse as the shared claim type, so required claims are present and
   well typed (`invalid_claims`). A logout token's `events` must hold the
   back-channel logout event with an object value, and it must have no `nonce`,
   not even `null`, so an ID token never passes as one.
8. `iss` equals the issuer exactly (`issuer_mismatch`).
9. `aud` contains the expected value: the resource for access tokens, the client
   for ID and logout tokens. An ID or logout token's `aud` must name no other
   client, since the SDK trusts no other audience (OIDC Core §3.1.3.7)
   (`wrong_audience`).
10. Time, with a 30-second leeway, matching auth's own `iat` skew:
   - expired when `now >= exp + 30` (`expired`);
   - not yet valid when `nbf > now + 30`, for both token types (`not_yet_valid`);
   - issued in the future when `iat > now + 30` (`issued_in_future`).
11. ID tokens only:
    - `nonce` equals the pending login's (`nonce_mismatch`);
    - `azp`, when present, is this client (`wrong_authorized_party`);
    - when the login sent `max_age`, `auth_time` must be present and
      `now <= auth_time + max_age + 30` (`authentication_too_old`).
12. Logout tokens only (OIDC Back-Channel Logout 1.0 §2.6):
    - `exp - iat` is at most 10 minutes (`lifetime_too_long`); auth signs each
      delivery attempt for two minutes;
    - `sub` or `sid` is present (`invalid_claims`).

Scope and step-up requirements are checked after validation, and fail with their
own categories.

## Signing keys

The SDK caches the issuer's key set:

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
- An RSA key whose modulus is under 2048 or over 8192 bits verifies nothing: its
  tokens fail with `bad_signature`.

This handles signing key rotation: auth publishes the new key before it signs with
it, so tokens from both keys verify during the overlap. Both SDKs' key caches work
with any JWKS URL, so auth also uses the Rust one for Google.

A key cache can also hold a fixed set, parsed by the rules above, for pinned keys,
offline verification and tests (`KeyCache::fixed(KeySet::parse(..))` in Rust,
`KeyCache.fixed(KeySet.parse(..))` in TypeScript). It is never fetched, so a `kid`
it lacks fails with `unknown_key`.

## Scopes

Scopes are space-separated strings on the wire (RFC 6749 §3.3), and each token is
printable ASCII without spaces, `"` or `\`. Each SDK types them, so a misspelled
scope does not compile: the Rust SDK declares an application's scopes once with a
macro, so a required scope is a type, and the TypeScript SDK with `defineScopes`,
whose names become a union that `AccessToken.require` accepts.

## Errors

Every SDK error has a category and, for most categories, a reason. Every SDK exposes
the same values, listed in `piquel_common::protocol::sdk`.

| Category | Meaning | Reasons |
| --- | --- | --- |
| `discovery` | Metadata could not be used | `issuer_mismatch`, `invalid_document`, `pkce_unsupported` |
| `keys` | The key set could not be used | `invalid_document`, `duplicate_key_id` |
| `invalid_token` | A token failed validation | see [Token validation](#token-validation) and [Login](#login) |
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

The Rust SDK's axum extractors report the request rows themselves. The TypeScript
SDK's `AuthError` reports them with two codes outside the shared categories,
`missing_token` and `invalid_request`, and every row with `toResponse()`.

The parameters are always written in the order `error`, `error_description`,
`scope`, `acr_values`, `max_age`, `resource_metadata`, with every value quoted, so
every SDK produces identical headers. `error_description` is printable ASCII without
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
   requirement it asks for with `acr_values` and `max_age`. Whenever discovery
   advertises `pushed_authorization_request_endpoint`, the SDK pushes the request
   there (RFC 9126), authenticated as at the token endpoint, and the URL carries
   only `client_id` and the returned `request_uri`; otherwise the URL carries the
   request. So a client auth requires to push still signs in. A push auth refuses
   is an `oauth` error, and one that cannot reach auth a `network` error. The
   pending login is kept until the callback, and auth redeems a code once, so a
   callback completes at most once.
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
   step-up login that falls short fails instead of being asked for again. A login
   that sent the signed-in user's ID token as `id_token_hint` fails unless the new
   ID token names the same `sub` (`invalid_token`, `subject_mismatch`).

A sign-in stays tied to its user and its authentication afterwards too (OIDC Core
§12.2, §5.3.2). A refresh that returns an ID token validates it as the sign-in's,
without `nonce` or `max_age`, then requires it to carry the sign-in over: the same
`sub` (`subject_mismatch`), the same `auth_time` and `acr`, and no `nonce` but the
sign-in's (`authentication_changed`). `UserInfo` must name the ID token's `sub`
(`subject_mismatch`). The Rust SDK checks these, taking the sign-in's ID token
claims in `refresh` and `userinfo`; `@piquel/auth` does not yet.

The SDK never sends the `audience` parameter auth accepts today; auth then uses the
client's default resource. They will send `resource` (RFC 8707) once auth supports
it.

Browser apps with no server are public clients and keep tokens in the page's memory
only. Only the pending login crosses a redirect, in `sessionStorage`, and its
callback deletes it. After a reload they authorize again with `prompt=none`; once
that comes back without a session, or a callback finds no login waiting, the page
load does not try again, so a user signed out at auth does not loop. A restore
after a failed step-up keeps the step-up's one retry spent for the minute after its
return.

## Sessions

Server-side apps keep each session in the browser, sealed, as the Rust SDK's axum
login routes and `@piquel/auth/server` do. The app stores nothing and implements
nothing: it holds a 32-byte cookie key, the same on every replica.

- **Cookies.** Each name carries the client ID, so apps sharing a host keep their
  own: `__Host-piquel-<client_id>-session`, `-step-up`, and `-login-<state>` for
  each pending login's slot. All are `Secure`, `HttpOnly`, `SameSite=Lax` and host-only.
- **Sealing.** AES-256-GCM, under a key HKDF-SHA256 derives from the cookie key with
  no salt and the `info` `piquel-auth session v1` for sessions, or
  `piquel-auth pending login v1` for pending logins. The associated data is the
  client ID and the cookie name, joined by NUL, so a value opens only as the cookie
  it was sealed as, for its own client. A sealed value is the base64url of the
  12-byte random nonce, the ciphertext and the tag. A cookie that does not open is
  never trusted: a session cookie is cleared, and any other is left alone.
- **The session.** Its JSON is `claims`, the validated claims of the sign-in's ID
  token or of the latest refresh's (not the token itself, which would not fit),
  `access_token`, `expires_at`, `scopes`, `refresh_token` and `ends_at`, with times
  in Unix seconds. `tests/sdk-vectors/sessions` pins it, so a cookie one SDK seals
  opens in the other. A session is over once `ends_at` passes, 12 hours after
  sign-in by default, whatever the cookie's `Max-Age`, which a copied cookie
  escapes, even when it comes while a refresh runs; refreshes keep it. A refresh replaces `claims` with the new ID token's,
  so a changed name or picture shows. The cookie's name and value must fit in 4096
  bytes, or browsers drop it, so a sign-in whose session would not fit fails, and a
  refresh whose session would not fit serves its request and leaves the cookie as
  it was, for the next request to refresh again. A typical session takes some
  2.5 KB; a long profile, many scopes, or access tokens that copy the profile
  (#279) make it larger.
- **Refresh.** The login routes take only confidential clients, whose refresh
  tokens auth does not rotate, and every login requests `offline_access`, which the
  client's registration must allow. A request
  whose access token expires within 30 seconds refreshes it, and its response sets
  the new cookie with `Cache-Control: no-store`: the axum layer adds it, and in
  TypeScript `login.respond(request, response)` does, which an app that forgets
  pays for only with another refresh. There is no lease: concurrent
  requests may each refresh, and each gets valid tokens. `invalid_grant` ends the
  session and clears its cookie. Any other failure, or no answer within 20 seconds,
  spends nothing: the session goes on while its access token is valid, and once
  that expired the request gets 503 and the cookie stays for the next request to
  try again, so a session auth ended never outlives its access token, even while
  auth is unreachable. A refreshed ID token that breaks the checks above, naming
  another user or changing the sign-in, ends the session. The session keeps the
  latest ID token's claims, and when one comes without a `nonce`, the sign-in's,
  which the next refresh is checked against. A sign-in that brings no refresh token
  ends with its access token.
- **Pending logins.** Each waits in one of three cookie slots, `-login-0` to
  `-login-2`, chosen by the first byte of its `state`'s SHA-256, with its own expiry
  10 minutes out. A login that lands in a taken slot replaces the one there, so two
  tabs signing in at once usually both complete. A callback reads and drops only the
  slot holding its `state`. Fixed slots bound the cookies even when responses to
  logins started at once cannot see each other's: each is at most 1000 bytes, so
  3000 together. A `return_to` too long for its slot returns home instead, or to
  `/` if home is too long too.
- **Step-up marker.** The `-step-up` cookie names the page a step-up returns to by
  the base64url of its SHA-256, for a minute.
- **Header size.** Common proxies refuse a `Cookie` header over 8 KiB. The session,
  pending logins and marker take at most some 7.2 KB of it, so an app's own cookies
  on the host share the rest.
- **Logout.** `POST <mount>/logout` revokes the session's refresh token at auth
  (RFC 7009), clears the cookies, and redirects to RP-initiated logout with
  `client_id`, since there is no ID token to send as `id_token_hint`. If auth
  cannot revoke it, the answer is 502 and the cookie stays, for the user to try
  again: clearing it would leave any copy refreshing. A sign-in revokes the refresh
  token of the session it replaces once its code is redeemed and its user checked,
  before setting the new session, and answers 502, keeping that session, when it
  cannot; the code is spent then, so the new grant is revoked too, and the user
  starts again. A revocation that takes over five seconds
  counts as failed, whatever the HTTP client's own timeout, so a hanging auth never
  holds a sign-in or logout open.
- **Redirects.** Without a session, or when a page asks to step up, only a browser
  navigating to a page with `GET` (`Sec-Fetch-Mode: navigate`) is redirected
  through login. Any other request gets 401, a client sending no fetch metadata
  included, since a `fetch` following a redirect to auth would fail its CORS
  check. The redirect returns to the path the browser asked for, the prefix of a
  nested axum router included; a TypeScript `Request` always carries its full URL.

So an app cannot end a session by itself. Clearing the cookie ends it in one
browser; a copy lives on until auth revokes the grant, through the app's logout or
a new sign-in, the user's own logout at auth, removal of the app, or the account
being disabled or deleted, and then ends at its next refresh, within an access
token's 5 minutes. Nothing orders the cookies responses set, either: a response
still in flight when the user signs out or in again can set the previous session
back, which then also ends with its access token. An app that needs sessions to end
sooner handles back-channel logout.

Changing the cookie key signs every user out of the app, but ends no grant at auth.
Whoever holds a leaked key can open captured cookies and read their refresh tokens,
which stay valid until auth's session ends and no longer rotate (#384), so only the
client secret then stands between them and new tokens. So after a leak, change the
key and rotate the client secret with no grace period too: `just auth client
rotate-secret <id> --grace 0`, or "at once" on the app's Secrets tab in the
developer console.

`SameSite=Lax` keeps the session cookie off other sites' posts, but not off a
sibling site's under the same domain: any `*.piquel.fr` page could post to an app as
its signed-in user. So logout, and every request that is not `GET`, `HEAD`, `OPTIONS`
or `TRACE` to a handler reading the session, are accepted only from the app's own
pages: `Sec-Fetch-Site: same-origin` when the browser sends it, and otherwise an
`Origin` equal to the app's, which `null` never is. Anything else gets 403 before
the session is read, with or without a cookie, so handlers need no CSRF token. A form
on a page with `Referrer-Policy: no-referrer` sends `Origin: null` with
`Sec-Fetch-Site: same-origin`, so it is accepted. Safe methods must not change
anything. An endpoint that other origins call with the cookie, such as a sibling
site's `fetch` with credentials under CORS, opts out explicitly (`CrossOrigin` in
axum, `session(request, { crossOrigin: true })` in TypeScript, where `session()`
otherwise answers with the 403 response to send) and guards against cross-site
request forgery itself.

## Back-channel logout

When auth ends a session, it posts a logout token (OIDC Back-Channel Logout 1.0) to
each client that received tokens from it, as an `application/x-www-form-urlencoded`
`logout_token` field. The SDKs keep no sessions, and a server-side app's sessions
end at their next refresh anyway. An app that must end them sooner gives its login
routes a handler (`LoginRoutes::on_backchannel_logout` in axum, `backchannelLogout`
in TypeScript), which mounts `POST <mount>/backchannel-logout`; the client
registers it as its back-channel logout URI. Without a handler there is no route.

The signed token is the authentication, so there is no origin check. The route
validates the token as above and passes it to the handler, which records what it
names where every replica sees it, so the app refuses those sessions itself: those
with the token's `sid` (auth's session ID), or without one, every session of its
`sub` (the user) signed in before the token's `iat`. A record can go a session
lifetime after its token. Auth delivers again until it gets a 200, so a handler
must be idempotent and return only once its record is durable. The route answers
200 once the handler succeeds, 400 with `{"error":"invalid_request"}` for an invalid
token, 503 when signing keys cannot be fetched and 500 when the handler fails, so
auth retries. Every answer has `Cache-Control: no-store`.

## Step-up

What an operation needs from the user's authentication is a
`step_up::StepUpRequirement`: an `acr` to meet, a maximum age of `auth_time`, or
both. Auth checks its own account APIs and authorization requests with the same
type's `check`, and the SDK checks tokens with it too:

- `acr` classes are ordered: `phr` meets every class, and
  `urn:piquel:acr:social` meets only itself. A token without `acr`, or with one the
  SDK does not know, meets no `acr` requirement.
- Gate on `acr`, never on `amr`. `amr` lists the methods a session used, not the
  assurance it reached: a recovered passkey signs in with `amr` `pop mfa user`
  but reports `acr` `urn:piquel:acr:social` until its recovery settles (see
  [account recovery](../security/account-recovery.md)).
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
challenge's values and returns to the same page. The sign-in must be the same
user's: a client holding the user's ID token sends it as `id_token_hint`, so auth
signs in that account only. A server-side client, whose session keeps only the ID
token's claims, records the user's `sub` in the pending login instead, and fails
the return, keeping the session unrevoked, when the new sign-in names another
account than that or than the session it would replace, as after switching
accounts in another tab. Either way, the refused sign-in's grant is revoked, so it
does not live on at auth unused. It checks this before revoking the session it replaces,
so it redeems the code first. If the resource still refuses on
that return, the client reports the error instead of redirecting again. A server-side
client recognizes the return by a short-lived marker, so a much later return counts
as a new action; a browser client by the session the return created, for a minute. The login check above also means a step-up sign-in never completes
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
`crates/common/tests/sdk_vectors.rs`, builds them from fixed test keys and the
shared claim types and signs them with auth's signer. `just sdk-vectors` rewrites
them, and `just test`, and so `just validate`, fails when they are stale. Every
SDK's test suite runs every case.
