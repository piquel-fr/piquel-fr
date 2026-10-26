# Managing your own OIDC clients

Any account can register OIDC clients for its own applications through the
account API on auth. Operators manage first-party clients with
`auth-service client` instead (see "OIDC clients" in the README), and those
never appear here.

These routes are first-party. Like the rest of the account API, they accept only
auth's own origin and the session cookie, and every request except
a `GET` needs the `x-piquel-csrf` header. "Confirmed" means a passkey
confirmation of the session from the last five minutes. Without one, the answer
is `403` with `step_up_required` (see
[step-up authentication](step-up-authentication.md)).

| Method and path | Needs | Does |
| --- | --- | --- |
| `GET /account/clients` | Session | Lists your clients |
| `POST /account/clients` | Confirmed | Registers a client. Answers `201` with the client and, for a confidential client, `client_secret`, shown only this once |
| `GET /account/clients/{id}` | Session | Shows a client and its secrets' `created_at` and `expires_at`, never their values |
| `PATCH /account/clients/{id}` | Confirmed | Replaces the settings you send |
| `POST /account/clients/{id}/disable` | Confirmed | Pauses a client: it can no longer sign users in, exchange codes or refresh tokens |
| `POST /account/clients/{id}/enable` | Confirmed | Lets a paused client work again, refresh tokens included. A client an administrator suspended answers `403` with `"code": "client_suspended"` |
| `POST /account/clients/{id}/secrets` | Confirmed | Gives a confidential client a new secret, shown only in this answer. Body `{"grace": "24h"}`: earlier secrets keep working that long (a day by default, at most `30d`; `"0"` revokes them now) |
| `DELETE /account/clients/{id}` | Confirmed | Deletes a client |

A client that is not yours, or was deleted, answers `404`, the same as an ID
that never existed.

## Settings

`POST` takes `kind` (`public` or `confidential`) and the settings below. `PATCH`
takes any of the settings, and keeps the others as they are. A client's ID and
kind never change.

| Field | Meaning |
| --- | --- |
| `display_name` | The name the consent screen shows, at most 80 characters |
| `redirect_uris` | 1 to 16 authorization callbacks, matched exactly, under the same rules as for operators' clients |
| `post_logout_uris` | Up to 16 pages the browser may return to after logout; none by default |
| `allowed_scopes` | Any of `openid`, `profile`, `email` and `offline_access`; `openid profile email` by default |
| `allow_refresh` | Whether the client may receive refresh tokens when it requests `offline_access`; `false` by default |
| `require_pushed_authorization_requests` | Whether the client must push its authorization requests to `/oauth/par` (RFC 9126), so none of their parameters travel through the browser; `false` by default |

A client also shows its `backchannel_logout_uri`, where auth tells it that a
user's session ended ([back-channel logout](../../README.md#back-channel-logout)).
Only an operator sets it for now, and your changes keep it.

Auth chooses the ID, `c_` followed by 20 random characters, so nobody can claim a
name like `piquel-admin`. Your clients are never trusted: users always see the
consent screen. Changing where auth may send the browser needs a confirmation,
so a stolen session cookie cannot add a redirect URI and collect authorization
codes.

## Limits and errors

An account can have 10 clients at once. Over that, `POST` answers `409` with
`"code": "client_quota_exceeded"` and `"limit": 10`. Deleting a client frees its
place. An account can also register at most 20 clients a day, deleted ones
included, since a deleted client's ID stays reserved forever. Over that, `POST`
answers `409` with `"code": "daily_client_limit_exceeded"` and `"limit": 20`.

Disabling is yours to undo. An administrator can also suspend a client, for
example one that is abused: it stops working, you still see it, with its
`suspended_at`, and you can delete it, but you cannot enable it until they lift
the suspension. It is then disabled until you enable it again.

An invalid setting answers `400` with `"code": "invalid_redirect_uri"` (for
`redirect_uris` and `post_logout_uris`) or `"invalid_client_metadata"`, as
RFC 7591 names them, `"field"` naming the setting, and a message that says what
to fix:

```json
{
  "error": "redirect_uris: redirect URI http://notes.example/callback must use https; http is allowed only on a loopback IP, e.g. http://127.0.0.1:8080/callback",
  "code": "invalid_redirect_uri",
  "field": "redirect_uris"
}
```

## What changes take effect

Every change applies to the next request, on every replica. Disabling or deleting a
client also stops its pending sign-ins and unused authorization codes. Removing a
redirect URI stops the pending sign-ins that use it.

Deleting a client also revokes its refresh tokens and removes its secrets and
the consents users gave it. Its ID stays reserved forever, because tokens name
their client in `aud`: no one, not even an operator, can register it again.

The `last_used_at` of a client is the last time a token was issued to it, to
within an hour. Each change is recorded in the client's history with your
account as the actor: `client_registered`, `client_updated` with the settings
that changed, `client_enabled`, `client_disabled`, `client_secret_rotated` and
`client_deleted`. Suspensions record `client_suspended` and
`client_suspension_lifted`, with the administrator as the actor. Secrets are never recorded.
