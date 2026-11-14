# Authorization flow

This page explains how auth runs OpenID Connect inside: what it stores at each
step of an authorization, how codes become tokens, and how refresh tokens,
revocation, userinfo and logout work. Read it before changing anything under
`apps/auth-service/src/oidc`. For the protocol as apps see it, read the
[OpenID Connect reference](../../user/reference/oidc.md) instead.

| Module | Holds |
| --- | --- |
| `oidc/mod.rs` | `OidcApplication`, its routes, the discovery document, client authentication and opaque tokens |
| `oidc/error.rs` | `OAuthError`, its status and `WWW-Authenticate` challenge, and the client redirect carrying it |
| `oidc/authorize/` | Authorization requests, pushed requests, the sign-in requirements and the consent decision |
| `oidc/inline.rs` | Completing a pushed request from a passkey sign-in on an app's own page |
| `oidc/policy.rs` | `ClientPolicy`, the check of the client's current registration |
| `oidc/token.rs` | The token, revocation and userinfo endpoints |
| `oidc/logout.rs` | RP-initiated logout |
| `web/auth/` | The sign-in, consent and logout pages the flow sends the browser to |

```text
app ──/oauth/par──▶ pending request (60 s) ──request_uri──┐
browser ──/oauth/authorize──▶ pending request (10 min) ◀──┘ claimed once
        │ session falls short?  ──▶ /login ─┐
        │ consent needed?       ──▶ /authorize (consent page)
        ▼                                    │ /oauth/authorize/resume
     code (2 min) ──redirect──▶ app ◀───────┘
app ──/oauth/token──▶ access + ID token (5 min), refresh family
```

## Opaque tokens

Pending requests, codes and refresh tokens are opaque tokens, written
`<prefix>_<id>.<secret>` (`OpaqueToken`). The prefix, `par_v1`, `pac_v1` or
`prt_v1`, binds a token to one purpose, so a code never passes as a refresh
token. The ID names the row. Only an HMAC of the secret is stored, under the
current token digest key, with that key's fingerprint; a lookup accepts the
digest under every configured key, so a change of key breaks nothing
([token digest keys](keys.md#token-digest-keys)).

## Pending authorizations

`/oauth/authorize` (`OidcApplication::authorize`) takes a request by query or
form post. It reads a pushed request's `client_id` and `request_uri` first, so no
other parameter can fail it. Otherwise it finds the client, which must be
enabled, matches `redirect_uri` exactly against its registration, and bounds
`state`. Until then an error answers as OAuth error JSON, which a browser's
navigation reads on auth's error page; from then on, every error goes back to the
client's redirect URI with `iss`, and `state` if the request had one
(`ClientRedirect`).

`AuthorizationParameters::validate` checks the rest the same way for browser and
pushed requests, one named step per check: no request object and no
`response_mode` but `query`, an `id_token_hint` that auth signed for this
client, which names the only account that may answer, `response_type=code`
(`unsupported_response_type` for another), an
S256 PKCE challenge, which only a confidential client may leave out, `state`, scopes and audience the client allows, `nonce`,
`max_age` and `prompt`. It returns a `ValidatedAuthorization`, whose `store`
saves the request and returns its token. The request is stored in
`authorization_requests` for ten minutes, with its first known `acr_values`
entry as its target `acr`. The browser carries its opaque token, the
transaction, from then on.

A client registered to push its requests is refused here with
`unauthorized_client`.

### Pushed requests

`/oauth/par` (`push_authorization`) authenticates the client as the token
endpoint does, validates the parameters the same way, and stores the request
for 60 seconds, answering `request_uri` with the token after
`urn:ietf:params:oauth:request_uri:`. Errors are JSON, since no browser is
involved.

The browser then brings `request_uri` and `client_id` to `/oauth/authorize`,
which ignores every other parameter. Claiming it (`claim`) works once, only for
that client: it gives the request a new secret and ten more minutes, and records
when it was claimed as when it started, so `prompt=login` and `max_age` count
from there.

## Sign-in and consent

`continue_authorization` decides where the browser goes. Every step that reads a
pending request first checks it against the client's registration as it is now
(`ClientPolicy`), so a client disabled, suspended or changed meanwhile leads the
browser nowhere it no longer allows.

1. **Does the session meet the request?** `session_satisfies` checks the hinted
   account, a sign-in after the request started for `prompt=login` or
   `max_age=0`, and the target `acr` and a positive `max_age` as a
   `StepUpRequirement`, the rule resources apply. The session's `acr` and
   `auth_time` come from [`SessionAuthentication`](sessions.md#authentication-claims).
2. **If not**, the browser goes to `/login?transaction=…`, with the target `acr`,
   so the page offers only the methods that reach it. Once signed in, the sign-in
   page continues the authorization in-process, or a provider's callback resumes
   it at `/oauth/authorize/resume`. With `prompt=none`, the client gets
   `login_required` instead. A passkey that signed in for this request but still
   falls short, as a recovered passkey in probation does, ends it with
   `unmet_authentication_requirements`, so the browser does not loop.
3. **A recovery that can be undone.** A sign-in made for the request, to an
   account with a recovery that can still be undone, first asks on the sign-in
   page whether it was the owner's.
4. **Consent.** A trusted client, or one the account already consented to for
   these scopes and audience, skips the consent page unless `prompt=consent`
   asks for it. Otherwise the browser goes to `/authorize?transaction=…`, or the
   client gets `consent_required` for `prompt=none`.

`decide` (`authorize/consent.rs`) consumes the pending request, whether the
consent page posted the decision or consent was implicit. An approval locks the
account and the session first, so a consent never commits after its session
ended, then share-locks the client (`ClientPolicy::share`) and checks its policy
again. An explicit approval saves the consent, per account, client, audience and
scopes, and records `ConsentGranted`. A denial redirects with `access_denied`.

### Codes

An approval issues an authorization code (`issue_code`), stored in
`authorization_codes` for two minutes. It is bound to the client, the redirect
URI, the PKCE challenge, the nonce, the scopes and audience, and the session, and
it copies the session's `SessionAuthentication` as it is then.

### On an app's own page

A trusted client may complete a pushed request with a passkey sign-in on its own
page, from an approved related origin ([passkey sign-in on your own
pages](../../user/apps/passkey-sign-in.md)). The ceremony claims the request
(`claim_inline`) and, once the passkey signed in, consumes it and issues its code
(`complete_inline`), which goes back to the page as JSON with `state` and `iss`.
The client must still be trusted and the origin approved. A request that needs
auth's own pages answers `interaction_required` instead, and the app sends the
browser to auth: one with `prompt=consent` or `prompt=none`, a sign-in that falls
short of it, or an account with a recovery that can still be undone.

## The token endpoint

`/oauth/token` (`token.rs`) first authenticates the client
(`authenticate_client`). A public client sends its ID alone. A confidential one
sends HTTP Basic credentials, compared in constant time with the digests of
every active secret, so the previous secrets work during a rotation's grace
period.

### Exchanging a code

`exchange_code` runs in one transaction:

1. It locks the code's account, then the code (`lock_code`), and checks that the
   form redeems it: the same client, the same `redirect_uri`, and a
   `code_verifier` matching its PKCE challenge, or none for a code issued
   without one. A failed check expires the code
   and records `CodeRedemptionFailed`, so a code is tried once. The account is
   locked whatever its status, and a disabled one isn't refused here. Its code
   fails as any other would: another client presenting it gets the usual
   rejection, and a replay of it is recorded.
2. It consumes the code, if its session and account are still active. A code
   redeemed before is a replay: the refresh families issued from it are revoked
   and `CodeReplayed` is recorded, before the request is rejected. The browser session stays signed in, since a leaked code
   exposes the client's callback, not the session cookie.
3. It locks the session, which must still be active, share-locks the client and
   checks its policy, and, for an untrusted client, reads the consent again, so
   a consent withdrawn since the code was issued fails the exchange.
4. It signs the tokens, with the claims the scopes release, and records
   `GrantIssued`.

Tokens are signed with the current key set ([keys](keys.md)). The access token
(`at+jwt`) is for the request's audience; an ID token is issued when the scopes
include `openid`, with the request's nonce. Both last five minutes
(`ACCESS_TOKEN_SECONDS`) and report the code's authentication, not the
session's current one. `sourceorigin.auth.tokens.issued{grant_type, token_type}` counts
them once the transaction commits.

### Refresh families

A refresh token is issued only when the client allows refresh and the scopes
include `offline_access`. The exchange creates a refresh family
(`refresh_token_families`): one grant, tied to its session, to the code it came
from and to the code's authentication. Its tokens expire with the session.

`redeem_refresh` (`crates/database/src/repositories/tokens`) locks the token's
account, session, family and client, in that order, and keeps the locks until
the new tokens commit, so a refresh waits for a logout or a disablement and then
fails on it. What it does depends on the client's kind:

- A **public** client's token rotates: it is consumed, and the response carries
  its replacement in the same family. Presenting a consumed token is a replay:
  the family is revoked and `GrantRevoked` records `refresh_replay`, so neither
  the thief nor the client refreshes again.
- A **confidential** client keeps its token, which is useless without the
  client's secret, so its refresh writes nothing.

A public client's retry is not a replay. Two tabs refreshing at once, or a
client retrying after a lost response, present the same token moments apart. A
token consumed less than `REFRESH_REUSE_SECONDS` (10) ago, whose successor is
still unused, is answered with that same successor, and the refresh writes
nothing. Two concurrent refreshes queue on the family's lock, so the second
finds the successor the first committed: they never mint two. Only the family's
previous token qualifies: once the successor rotates in turn, or the window has
passed, the old token is a replay.

A successor names the token it replaced (`refresh_tokens.predecessor_id`,
unique), and only its digest is stored, like every token's. To answer a retry
with it, auth derives a successor's secret rather than drawing it at random: an
HMAC of the replaced token's secret, under a key derived from the token digest
key and keyed by the successor's ID (`TokenDigestKeys::successor`). A retry
presents the replaced token, so auth derives the successor again and checks it
against the stored digest. The database holds nothing usable, not even sealed:
deriving a successor takes both the key and the token it replaced. Successors
form a chain, though. Anyone with the key, the successor IDs from a database
read and any earlier token of a family, however old, can derive its live token.
So a spent token is only harmless while the key stays secret.

A family whose client no longer allows refresh, its audience or its scopes is
revoked on its next use (`policy_rejected`). A refresh may narrow the scopes,
never add any. The new tokens keep reporting the family's original
authentication (OIDC Core §12.2).

A family ends with its session: revoking a session revokes its families in the
same transaction ([sessions](sessions.md#expiry-and-revocation)), and removing an
app's access, deleting a client or disabling an account revokes theirs.

## Revocation and userinfo

`/oauth/revoke` (RFC 7009) authenticates the client, revokes the family of the
refresh token it sends if that token is its own, and records `GrantRevoked`
(`client_revoked`). It answers `200` whatever the token, so it reveals nothing.
Access tokens cannot be revoked; they expire within five minutes.

`/oidc/userinfo` verifies a bearer access token against the current key set and
issuer, requires the `openid` scope, and answers the profile claims the token
itself carries, released by its scopes. It reads nothing from the database.

## Logout

RP-initiated logout takes two requests:

1. `/oidc/logout` (`start_logout`) validates the request: an `id_token_hint`
   auth signed, which may be expired and signed by a retired key, a `client_id`
   matching the hint's audience, and a `post_logout_redirect_uri` registered
   exactly for that client. It then sends the browser to auth's `/logout` page
   with the same parameters.
2. The page asks the user to confirm. Its form validates the parameters again and
   signs the browser out (`end_session`), recording
   `RelyingPartyLogout` with the client that asked, or `Logout` when none is
   named. The browser goes on to the redirect URI with `state`, or to sign-in.

Signing out revokes the session, which tells every app that received tokens from
it ([back-channel logout](sessions.md#back-channel-logout)).

## Discovery

`OidcApplication::metadata` builds the discovery document once at startup, from
the `ALL` lists of the enums the endpoints parse into, so nothing is advertised
that is not handled. It is served at `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server`, and JWKS at `/.well-known/jwks.json`
from the current key set; all three are cacheable for an hour.
