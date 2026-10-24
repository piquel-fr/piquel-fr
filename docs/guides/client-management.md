# Managing your own OIDC clients

Any account can register OIDC clients for its own applications in the developer
console, at `auth.piquel.fr/developers` (`piquel.fr/developers` redirects there).
Operators manage first-party clients with `auth-service client` instead (see
"OIDC clients" in the README), and those never appear in the console.

The console's pages are auth's own, under its session cookie. "Confirmed" means a
passkey confirmation of the session from the last five minutes. A page asks for it
before it posts a change that needs one, and a change posted without one is refused
and asked again (see [step-up authentication](step-up-authentication.md)).

| Page | Needs | Does |
| --- | --- | --- |
| `/developers` | Session | Lists your apps: name, ID, kind, status and when each was last used |
| `/developers/new` | Confirmed | Registers an app. A confidential app's secret shows in the answer, only this once |
| `/developers/clients/{id}` | Session | What an OpenID Connect library needs: issuer, discovery URL, client ID, client authentication and scopes, and a Rust example |
| `/developers/clients/{id}/settings` | Session; Confirmed to change the redirect or post-logout URIs, and to delete | Changes the settings, disables or enables the app, and deletes it |
| `/developers/clients/{id}/secrets` | Confirmed to rotate | A confidential app's secrets, with when each was made and stops working, never their values. A new secret shows in the answer, only this once; earlier ones keep working for the grace period you choose (none, an hour, a day, a week or 30 days) |

An app that is not yours, or was deleted, answers `404`, the same as an ID that
never existed. A secret is never in a URL, a cookie or the browser's storage, and,
with the page's script, reloading the page that showed it does not post the form
again.

## Settings

| Setting | Meaning |
| --- | --- |
| Name | The name the consent screen shows, at most 80 characters |
| Kind | A web app with a backend (confidential, signs in with a client secret) or an app running in the browser or on a device (public, with PKCE alone). Both sign in with S256 PKCE, and the kind never changes |
| Redirect URIs | 1 to 16 authorization callbacks, one per line, matched exactly, under the same rules as for operators' clients |
| Post-logout URIs | Up to 16 pages the browser may return to after logout, one per line; none by default |
| Scopes | Any of `openid`, `profile`, `email` and `offline_access`; `openid profile email` by default |
| Refresh tokens | Whether the app may receive refresh tokens when it requests `offline_access`; off by default |
| Pushed requests | Whether the app must push its authorization requests to `/oauth/par` (RFC 9126), so none of their parameters travel through the browser; off by default |

An app also shows its back-channel logout URI, where auth tells it that a user's
session ended ([back-channel logout](../../README.md#back-channel-logout)). Only an
operator sets it for now, and your changes keep it.

Auth chooses the ID, `c_` followed by 20 random characters, so nobody can claim a
name like `piquel-admin`. Your apps are never trusted: users always see the
consent screen. Changing where auth may send the browser needs a confirmation, so
a stolen session cookie cannot add a redirect URI and collect authorization codes.
An invalid setting is refused with what to fix, beside its input.

## Limits

An account can have 10 apps at once. Deleting one frees its place. An account can
also register at most 20 apps a day, deleted ones included, since a deleted app's
ID stays reserved forever.

Disabling is yours to undo. An administrator can also suspend an app, for example
one that is abused: it stops working, you still see it, and you can delete it,
but you cannot enable it until they lift the suspension. It is then disabled until
you enable it again.

## What changes take effect

Every change applies to the next request, on every replica. Disabling or deleting
an app also stops its pending sign-ins and unused authorization codes. Removing a
redirect URI stops the pending sign-ins that use it.

Deleting an app also revokes its refresh tokens and removes its secrets and the
consents users gave it. Its ID stays reserved forever, because tokens name their
client in `aud`: no one, not even an operator, can register it again.

An app's "last used" is the last time a token was issued to it, to within an hour.
Each change is recorded in the client's history with your account as the actor:
`client_registered`, `client_updated` with the settings that changed,
`client_enabled`, `client_disabled`, `client_secret_rotated` and `client_deleted`.
Suspensions record `client_suspended` and `client_suspension_lifted`, with the
administrator as the actor. Secrets are never recorded.
