# Introduction

A piquel.fr account signs you in with a passkey: a key your device or password
manager keeps, which your fingerprint, face or PIN unlocks. There is no
password to remember or leak. You can also link a GitHub or Google account to
sign in with.

Your account lives at [auth.piquel.fr](https://auth.piquel.fr). Its settings,
at `auth.piquel.fr/settings`, manage your passkeys, email addresses, devices,
the apps you signed in to, your notifications and your data.

## Words this guide uses

- **Handle:** your account's public name, such as `alice`. You sign in with it,
  and apps receive it.
- **Passkey:** a credential bound to your account. An account can have several,
  one per device or password manager.
- **Session:** one device signed in to your account. Settings list your devices,
  and you can sign any of them out.
- **App:** a website or service that signs you in with your piquel.fr account.
  The first time, it asks for your consent, naming what it will receive. Apps
  Piquel runs itself don't ask.
- **Passkey confirmation:** sensitive changes, such as removing a passkey, need
  you to have used your passkey in the last five minutes. If you haven't, Piquel
  asks for it again first, even though you are signed in.

## Building an app

Any account can register apps in the developer console, at
`auth.piquel.fr/developers`. An app then signs its users in through OpenID
Connect, with the Rust SDK (`piquel-auth`), the TypeScript SDK
(`@piquel/auth`), or any OpenID Connect library:

- [Registering an app](apps/register-an-app.md) covers the console.
- [Step-up authentication](apps/step-up.md) asks for a fresh passkey before a
  sensitive action.
- [Back-channel logout](apps/back-channel-logout.md) ends an app's session when
  the user's session at auth ends.
- [OpenID Connect](reference/oidc.md) lists the endpoints, tokens and claims.
