# Back-channel logout

Have Origin Auth tell your app's server when a user's session at Origin Auth ends, so your
app can end its own session for them at once. Without it, an app using the
SDKs' login routes learns that a session ended at its next refresh, within five
minutes.

Origin Auth sends a logout token whenever a session ends before it expires: for
example when the user signs out, signs in to another account, signs out their
other devices or removes a passkey, or an administrator ends their sessions or
disables their account. It follows OpenID Connect Back-Channel Logout 1.0.

## Before you start

- You need an [app you registered](register-an-app.md), with a server.
- Your server must be reachable over HTTPS from the public internet. SourceOrigin
  never posts to a loopback, private or tailnet address, and never follows a
  redirect.

## Set the back-channel logout URI

1. Open the app's **Settings** tab in the developer console.
2. Fill in **Back-channel logout URI**, such as
   `https://notes.example/auth/backchannel-logout`. The SDKs' login routes serve
   it at `/backchannel-logout` beside their callback. Origin Auth's server posts
   to it, so it must use HTTPS and be reachable from the internet: an IP address
   that isn't public, such as `127.0.0.1`, is refused, and a name that resolves to
   one gets no logout tokens.
3. Select **Save changes**.

Operators set it for SourceOrigin's own apps with
`auth-service client update <id> --backchannel-logout-uri <uri> --reason "…"`: see
[OIDC clients](../../dev/operations/clients.md).

## Handle logout tokens

With the SDKs' login routes, give them a handler. The route validates each
token, then hands it to your handler, which records what it ends where every
replica of your app sees it. In Rust:

```rust
let auth = auth.on_backchannel_logout(move |logout| {
    if let LogoutScope::Session(sid) = logout.scope() {
        // Record `sid` as ended, in your app's database.
    }
    async { Ok::<_, Infallible>(()) }
});
```

In TypeScript, pass a `backchannelLogout` function in the login routes'
options. Your app then refuses every session the token names: the user's
session whose `sid` it carries.

Without an SDK, validate the token as Back-Channel Logout 1.0 §2.6 says: its
signature against auth's keys, `iss`, `aud`, `iat`, `exp`, the `events` claim,
and no `nonce`. Then end your sessions with its `sid`, unless you already
applied its `jti`, and answer `200` either way. [Logout tokens](#logout-tokens)
shows what one holds.

## Stop receiving logout tokens

Empty **Back-channel logout URI** on the app's **Settings** tab, and select
**Save changes**. Operators use `--no-backchannel-logout-uri`.

## Check that it works

1. Sign in to your app in one browser.
2. In another browser, open your Origin Account's **Devices** settings, and
   select **Sign out** next to the first browser.
3. Your handler receives a logout token naming that browser's session, within
   a few seconds, and your app treats the first browser as signed out.

## Troubleshooting

- **No token arrives.** Check that the URI uses HTTPS, resolves to public
  addresses, and answers without a redirect. An app on a private route, or on
  your machine, never receives one.
- **A token arrives twice.** Origin Auth delivers again until your server answers
  `200`, so make your handler idempotent: a repeat carries the same `jti`.
- **Deliveries stop after an error.** A `400` or another `4xx` answer ends the
  delivery for good. Timeouts, `408`, `429` and `5xx` are retried with backoff,
  for up to an hour after the session ended. Past that, your app's session lasts
  until its next refresh, or until it expires.

## Logout tokens

Origin Auth posts `logout_token=<JWT>` as `application/x-www-form-urlencoded` to the
URI. The token is signed with auth's token key, with the header
`typ: logout+jwt`:

```json
{ "iss": "https://auth.sourceorigin.dev", "aud": "<client_id>", "iat": 1760000000,
  "exp": 1760000120, "jti": "<delivery id>", "sub": "<user id>",
  "sid": "<session id>",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }
```

`sid` is the `sid` of the ID tokens your app received from that session. Each
attempt is signed afresh, valid for two minutes, and carries the same `jti`.
