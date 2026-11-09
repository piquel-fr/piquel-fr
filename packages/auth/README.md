# @sourceorigin/auth

The TypeScript SDK for [auth.sourceorigin.dev](https://auth.sourceorigin.dev). It signs users in
to your app with their Origin Account, and validates the access tokens auth
issues. It is ESM only and has no runtime dependencies: it uses `fetch` and
WebCrypto, so it runs in browsers, Node 22+, Bun and Cloudflare Workers.

## Install

The package is not on npm yet. Build it from a checkout of
[the repository](https://github.com/sourceorigin-dev/sourceorigin), then install it from
there:

```console
pnpm install --frozen-lockfile
pnpm --filter @sourceorigin/auth build
npm install <checkout>/packages/auth
```

## Sign users in

On a server, `@sourceorigin/auth/server` serves the login routes under `/auth` and keeps
each user's session in a sealed cookie, so your app stores nothing:

```ts
import { Issuer } from '@sourceorigin/auth';
import { CookieKey, Login } from '@sourceorigin/auth/server';

const issuer = await Issuer.discover('https://auth.sourceorigin.dev');
const login = new Login(
  issuer.client({
    clientId: 'notes-web',
    clientSecret: process.env.CLIENT_SECRET!,
    redirectUri: 'https://notes.example/auth/callback'
  }),
  // `openssl rand -base64 32`, the same on every replica.
  { cookieKey: CookieKey.fromBase64(process.env.COOKIE_KEY!), scopes: ['profile'] }
);

export async function fetch(request: Request): Promise<Response> {
  const routed = await login.handle(request);
  if (routed) return routed;
  const user = await login.session(request);
  if (user instanceof Response) return user;
  if (!user) return login.respond(request, login.signIn(request));
  return login.respond(request, new Response(`Hello ${user.name}`));
}
```

[Signing in with TypeScript](https://docs.sourceorigin.dev/user/apps/sign-in-typescript.html)
explains it, and what to register first.

## Browser apps

`@sourceorigin/auth/browser` signs users in to a page with no server, keeping their
tokens in memory: see
[browser apps](https://docs.sourceorigin.dev/user/apps/browser-apps.html).

## APIs

`issuer.resource()` validates the access tokens an API receives, with its scopes
declared as types: see
[protecting an API](https://docs.sourceorigin.dev/user/apps/protect-an-api.html).

## Learn more

- [How sign-in works](https://docs.sourceorigin.dev/user/apps/how-sign-in-works.html)
- [Step-up authentication](https://docs.sourceorigin.dev/user/apps/step-up.html)
- [Back-channel logout](https://docs.sourceorigin.dev/user/apps/back-channel-logout.html)
- [The SDK's design](https://docs.sourceorigin.dev/dev/architecture/sdk.html), to change
  it
