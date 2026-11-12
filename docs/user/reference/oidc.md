# OpenID Connect

auth.sourceorigin.dev is an OpenID Connect provider. This page lists what it
implements, for an app that talks to it directly or through an OIDC library.

## Discovery

Discovery is served at both `/.well-known/openid-configuration` (OIDC) and
`/.well-known/oauth-authorization-server` (RFC 8414, read by OAuth-only and MCP
clients); the two are the same document. JWKS is `/.well-known/jwks.json`. All three
are cacheable for an hour and readable from any origin, without credentials.
Every authorization response redirected to a client, success or error, carries
`iss` (RFC 9207), so clients that use several issuers can reject mix-ups; discovery
advertises `authorization_response_iss_parameter_supported`.

## Pushed authorization requests

A client may push its authorization request (RFC 9126) instead of sending it
through the browser: it posts the usual parameters to `/oauth/par`, authenticated
as at the token endpoint, and receives a `request_uri` valid for 60 seconds. The
browser then opens `/oauth/authorize?client_id=…&request_uri=…`. The `request_uri`
works once, only for that client, and auth ignores every other parameter sent
with it. A pushed request is validated exactly like a browser one, but its errors
come back as JSON. Discovery advertises `pushed_authorization_request_endpoint`.
Client-hosted request objects (`request` and `request_uri` from RFC 9101) are not
supported.

## Codes, tokens and consent

The endpoints implement code exchange, RS256 ID/access tokens, userinfo, opt-in
refresh tokens, revocation, RP-initiated and back-channel logout. A code
is tried once: a redemption by another client, with another `redirect_uri` or a
wrong `code_verifier` expires it and records `code_redemption_failed`, so it
can't be tried again. Every step of an authorization checks the client's registration
as it is then, under a share lock when it issues a code or tokens: a client
disabled, suspended or changed meanwhile gets nothing it no longer allows. Access tokens are
intended for the configured client audience. Only requested claims are released;
passkey-only accounts have no email claim. Browser clients should keep tokens in
memory and use SSO again after reload. Refresh permission is off unless explicitly
enabled and `offline_access` is allowed/requested. A public client's refresh token
rotates: each refresh answers with a new one, and presenting a spent one revokes
the whole grant, so a stolen copy is caught as soon as both are used. The one
exception is a refresh repeated within 10 seconds, such as two tabs refreshing
at once or a retry after a lost response: presenting the token just replaced
answers with the same new one, as long as that one hasn't been used yet. A confidential
client keeps its token, and a refresh answers with none: without the client's
secret the token is useless, so it needs no rotation (RFC 9700 §4.14), and a
refresh writes nothing.

Consent is remembered per user,
client and scope; explicitly trusted clients bypass consent. The consent page
names the host the app sends the browser back to and the signed-in account, which
can switch to another, and labels an app an account registered as unverified,
with its owner's handle. Users see the apps
they consented to, or whose refresh grants still work, under Connected apps in
settings (`/settings/apps`), and remove an app's access there: its refresh grants
end, it asks for consent again, and its outstanding codes stop working. Access
tokens it already holds expire within five minutes. The settings API serves them too
(`GET /account/apps`, `DELETE /account/apps/{client_id}`). An administrator removes
one the same way from the account's Connected apps page on the dashboard, and an
operator with `auth-service account <user> apps remove <client-id>`, each with a
reason the owner sees in their history.

## Authentication claims

ID and access tokens report how the browser session behind the grant
authenticated:

| Claim | Values |
| --- | --- |
| `acr` | `phr` once a passkey confirmed the session, which a passkey sign-in does: phishing-resistant multi-factor authentication ([OpenID Connect EAP ACR Values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)). `urn:sourceorigin:acr:social` for a session signed in with GitHub or Google only, the provider's authentication, whatever it was; and for one signed in with a recovered passkey until its recovery settles |
| `amr` | Every method the session used (RFC 8176): `pop`, `mfa` and `user` for a passkey, which proves possession of a key and requires user verification; `fed` for a provider sign-in. RFC 8176 registers no value for federation, so `fed` is SourceOrigin's own. It says how, not how strongly: gate on `acr` |
| `auth_time` | The latest authentication at the session's `acr`: its last passkey confirmation, or else its sign-in |

`phr` satisfies a `urn:sourceorigin:acr:social` requirement, not the reverse. Both values
are listed in discovery's `acr_values_supported`. An authorization request may send
`acr_values` in order of preference: the first known value becomes its target, and
unknown values are ignored. A session below the target signs in again, on a login
page offering only passkeys for `phr`; with `prompt=none` the request fails with
`login_required`. If a passkey sign-in for the request still falls short, as a
recovered passkey does, the request fails with `unmet_authentication_requirements`
rather than asking again. With no known value, the tokens report what the session
reached.

Signing in again (`prompt=login`, `max_age`, a target) re-authenticates the
browser's session rather than starting another, so `sid` stays the same: a passkey
confirms it, and a social sign-in renews it only before any passkey confirmation,
since it would lower `acr`. Every re-authentication, including a passkey
confirmation for a settings change, replaces the session cookie, so a copied cookie
never gains the new authentication. Signing in as another account revokes the previous
session. A refresh token keeps reporting the authentication of the code it came
from, even after the session re-authenticates.

An API that needs a stronger or more recent sign-in answers with an RFC 9470
step-up challenge, and its client signs the user in again with that challenge's
`acr_values` and `max_age`. [Step-up authentication](../apps/step-up.md)
explains how to choose a requirement and handle the challenge.
