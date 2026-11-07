# Back-channel logout

When a session at auth ends, every client that received tokens from it and
registered a back-channel logout URI is told (OIDC Back-Channel Logout 1.0), so
it can end its own session for the user. Operators set it with
`--backchannel-logout-uri`, and owners in the developer console. Every way a session ends early does
this: signing out, RP-initiated logout, signing in to another account, signing out
other devices, removing a passkey, unlinking a provider, reporting a history entry,
and an administrator revoking sessions or disabling the account.
`--no-backchannel-logout-uri`, or emptying the console's field, stops it.

## Receiving a logout token

Auth posts `logout_token=<JWT>` as `application/x-www-form-urlencoded` to the URI.
The token is signed with auth's token key, with the header `typ: logout+jwt`:

```json
{ "iss": "https://auth.piquel.fr", "aud": "<client_id>", "iat": 1760000000,
  "exp": 1760000120, "jti": "<delivery id>", "sub": "<user id>",
  "sid": "<session id>",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }
```

`sid` is the `sid` of the ID tokens the client received. A client must validate the
token as Back-Channel Logout 1.0 §2.6 says (signature, `iss`, `aud`, `iat`, `exp`,
`events`, no `nonce`), end its sessions with that `sid` unless it already applied the
token's `jti`, and answer `200` either way. The SDKs' login routes validate the
token at `POST <mount>/backchannel-logout` and hand it to the app's handler; apps
without one rely on their sessions ending at the next refresh, within five
minutes. A `400` fails the delivery for good;
timeouts and `5xx` are retried with backoff for up to an hour. Every attempt is
signed afresh and carries the same `jti`, so a receiver applies a repeat only once.
The URI must be HTTPS and resolve to public addresses, and redirects are not
followed.
Delivery is asynchronous: an application's session may outlive auth's by the few
seconds a delivery takes, or until it expires if the client cannot be reached.
