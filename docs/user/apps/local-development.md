# Developing on your machine

Run your app on your own machine while it signs users in with the real
auth.piquel.fr. Piquel accepts plain HTTP redirect URIs on a loopback address,
so you don't need a certificate or a public hostname.

## Before you start

- You need a piquel.fr account with a passkey.
- Pick the address your app listens on locally, such as `127.0.0.1:3000`.

## Register a development app

Register a separate app for development, rather than adding your machine to
the production app. Its secret then never needs to leave your machine, and
nothing you try locally changes what production users see.

1. [Register an app](register-an-app.md) named, for example, **Notes (dev)**,
   of the same kind as your production app.
2. In **Redirect URIs**, enter the callback on your machine, such as
   `http://127.0.0.1:3000/auth/callback`.
3. Select **Register app**, and save the secret as [below](#keep-the-secret-out-of-the-repository).

### Which redirect URIs work locally

Plain HTTP is accepted only on a loopback IP address:

| Redirect URI | Accepted |
| --- | --- |
| `http://127.0.0.1:3000/auth/callback` | Yes |
| `http://[::1]:3000/auth/callback` | Yes |
| `https://notes.example/auth/callback` | Yes |
| `http://localhost:3000/auth/callback` | No: `localhost` is a name, not an IP address |
| `http://192.168.1.20:3000/auth/callback` | No: a LAN address needs HTTPS |

Redirect URIs match exactly, port and path included. Register one per port you
use, up to 16, and open your app at that same address in the browser, such as
`http://127.0.0.1:3000`, not `http://localhost:3000`: your app's sign-in
cookies belong to the host they were set on.

## Keep the secret out of the repository

Give your app its secret through the environment, never in a file you commit:

```console
export PIQUEL_CLIENT_SECRET='pqcs_…'
cargo run
```

The Rust example on the app's **Overview** tab reads `PIQUEL_CLIENT_SECRET`,
and its cookie key from `PIQUEL_COOKIE_KEY`. If you keep them in a file such as
`.env`, list it in `.gitignore`. Every Piquel client secret starts with `pqcs_`,
so secret scanners can recognize one that is committed anyway. If that happens,
[rotate it](rotate-secrets.md#after-a-leak).

For the cookie key, `openssl rand -base64 32` makes one to keep in the same
place. The SDKs can also generate a random one at startup, for development:
`CookieKey::generate()` in Rust, `CookieKey.generate()` in TypeScript. Every
restart then signs you out.

## Check that it works

1. Start your app, and open it at the address you registered.
2. Sign in. Piquel shows the consent screen for **Notes (dev)**, naming
   `127.0.0.1` as where it sends you back.
3. Select **Continue**. Your app receives you at its callback, signed in.

## Troubleshooting

- **The console refuses the redirect URI with "must use https; http is allowed
  only on a loopback IP".** Use `127.0.0.1` or `[::1]` instead of `localhost`
  or a LAN address.
- **Auth answers `redirect_uri is not registered for this client; it must match
  exactly`.** The port or path your app sends differs from the registered one.
  Register the URI your app sends, character for character.
- **Back-channel logout never reaches your machine.** Piquel posts logout
  tokens only to HTTPS addresses on the public internet. Locally, your app's
  sessions end at their next refresh instead, within five minutes.

[Troubleshooting](troubleshooting.md) covers the other errors your app may
see.
