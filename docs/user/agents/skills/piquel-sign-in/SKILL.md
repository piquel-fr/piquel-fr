---
name: piquel-sign-in
description: >
  Add sign-in with a piquel.fr account to a web app with a backend, using the
  Rust SDK (piquel-auth, with axum) or the TypeScript SDK (@piquel/auth). Use
  when the person wants their app's users to sign in with piquel.fr, or asks
  to integrate auth.piquel.fr, its OpenID Connect provider or its SDKs.
---

# Add piquel.fr sign-in

auth.piquel.fr is an OpenID Connect provider. Both SDKs have server-side login
routes that run the whole sign-in: `GET /auth/login`, `GET /auth/callback` and
`POST /auth/logout`. The session lives in the browser, in a cookie sealed with
the app's cookie key, so the app stores nothing.

The guides behind this skill:

- Registering an app: https://docs.piquel.fr/user/apps/register-an-app.html
- OpenID Connect reference: https://docs.piquel.fr/user/reference/oidc.html
- Rust SDK: https://github.com/piquel-fr/piquel-fr/tree/main/crates/auth-sdk
- TypeScript SDK: https://github.com/piquel-fr/piquel-fr/blob/main/packages/auth/README.md

## 1. Ask the person to register the app

You can't register it: the developer console asks for a passkey confirmation,
which only the person can give. Ask them to open
https://auth.piquel.fr/developers/new and fill in:

- **App name**: the name users see when they sign in.
- **Does your app have a backend that can keep a secret?**: **Yes, a web app
  with a backend**. The login routes need a client secret.
- **Redirect URIs**: the callback, `https://<app host>/auth/callback`. Auth
  compares it with the app's as a whole string, so it must match exactly. For
  local development, use the piquel-dev-setup skill.
- **Post-logout URIs**: `https://<app host>/`, if users should come back to the
  app after signing out.
- **Scopes**: `openid`, `profile` for the user's handle, name and picture,
  `email` only if the app needs it, and `offline_access`. The login routes
  request `offline_access` on every sign-in, and auth refuses a sign-in that
  asks for a scope the app may not request.
- **Allow refresh tokens**: checked. Without refresh tokens, a session ends
  with its access token, within five minutes.

After **Register app**, the console shows the client secret once. Ask the
person to put it in the app's environment themselves, and not to paste it into
the conversation. It never goes in the repository. They then give you the
**Client ID** from the app's page, which is public.

## 2. Read the configuration from the environment

| Variable | Value |
| --- | --- |
| `PIQUEL_ISSUER` | `https://auth.piquel.fr`, with no trailing slash. Optional |
| `PIQUEL_CLIENT_ID` | The client ID |
| `PIQUEL_CLIENT_SECRET` | The client secret |
| `PIQUEL_REDIRECT_URI` | The registered callback, exactly |
| `PIQUEL_COOKIE_KEY` | 32 random bytes in standard base64, from `openssl rand -base64 32` |

The cookie key must be the same on every replica, and changing it signs every
user out. Read both secrets from a file when `<NAME>_FILE` is set, such as
`PIQUEL_CLIENT_SECRET_FILE`, since some hosts, piqueld among them, mount
secrets as files. If the project keeps local settings in a file such as
`.env`, check that the file is in `.gitignore` before anything is written to
it.

## 3a. Rust, with axum

Add the SDK, with axum at the version it uses:

```toml
[dependencies]
piquel-auth = { git = "https://github.com/piquel-fr/piquel-fr", features = ["axum"] }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

Then mount the login routes and their layer:

```rust
use axum::{Router, routing::get};
use piquel_auth::{
    ClientConfig, Credentials, Issuer,
    axum::{CookieKey, LoginRoutes, MaybeSignedIn, SignedIn},
};
use std::{env, error::Error, fs};

/// The secret `name`: read from the file `<name>_FILE` names, or else from `<name>`.
fn secret(name: &str) -> Result<String, Box<dyn Error>> {
    match env::var(format!("{name}_FILE")) {
        Ok(path) => Ok(fs::read_to_string(path)?.trim().to_owned()),
        Err(_) => Ok(env::var(name)?),
    }
}

/// A public page, which greets the user when signed in.
async fn home(MaybeSignedIn(user): MaybeSignedIn) -> String {
    match user {
        Some(user) => format!("Hello {}", user.name()),
        None => "Sign in at /auth/login".into(),
    }
}

/// A page for signed-in users only: a browser without a session goes through
/// sign-in and comes back.
async fn notes(user: SignedIn) -> String {
    format!("Notes of {}", user.name())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let issuer = env::var("PIQUEL_ISSUER").unwrap_or_else(|_| "https://auth.piquel.fr".into());
    let issuer = Issuer::discover(&issuer).await?;
    let config = ClientConfig {
        client_id: env::var("PIQUEL_CLIENT_ID")?.parse()?,
        credentials: Credentials::Secret(secret("PIQUEL_CLIENT_SECRET")?.into()),
        redirect_uri: env::var("PIQUEL_REDIRECT_URI")?.parse()?,
    };
    let key = CookieKey::from_base64(&secret("PIQUEL_COOKIE_KEY")?)?;
    // Scopes besides `openid` and `offline_access`, which every sign-in requests.
    let auth = LoginRoutes::new(issuer.client(config), key)?.scopes("profile".parse()?);
    let app = Router::new()
        .route("/", get(home))
        .route("/notes", get(notes))
        .nest("/auth", auth.router())
        .layer(auth.layer());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- `SignedIn` redirects a browser navigating to the page through sign-in, and
  answers any other request, such as a `fetch`, with 401. `MaybeSignedIn` is
  for pages that work signed out too.
- Link to `/auth/login?return_to=/notes` to sign in and come back to a page.
- Sign out with a form that posts to `/auth/logout` from the app's own pages.
- Mount the routes elsewhere with `.mounted_at("/account")`, and change where
  users land with `.after_login(...)` and `.after_logout(...)`, which must be a
  registered post-logout URI.

## 3b. TypeScript

`@piquel/auth` runs on Node 22 or later, Bun and Cloudflare Workers.
`@piquel/auth/server` takes a standard `Request` and returns a `Response`, so
it fits Node, Bun, Workers, Hono and SvelteKit. The package isn't published to
npm yet: ask the person how the project should get it before you add it.

```ts
import { Issuer } from '@piquel/auth';
import { CookieKey, Login } from '@piquel/auth/server';

const issuer = await Issuer.discover(process.env.PIQUEL_ISSUER ?? 'https://auth.piquel.fr');
const login = new Login(
  issuer.client({
    clientId: process.env.PIQUEL_CLIENT_ID ?? '',
    clientSecret: process.env.PIQUEL_CLIENT_SECRET,
    redirectUri: process.env.PIQUEL_REDIRECT_URI ?? ''
  }),
  // Scopes besides `openid` and `offline_access`, which every sign-in requests.
  { cookieKey: CookieKey.fromBase64(process.env.PIQUEL_COOKIE_KEY ?? ''), scopes: ['profile'] }
);

export async function handle(request: Request): Promise<Response> {
  const routed = await login.handle(request); // the routes under /auth, or null
  if (routed) return routed;
  const user = await login.session(request); // null, the signed-in user, or a response
  if (user instanceof Response) return user; // 403 from another site, or 503
  // A browser without a session goes through sign-in and comes back.
  if (!user) return login.respond(request, login.signIn(request));
  // `respond` adds the cookies the session needs, such as a refreshed one.
  return login.respond(request, new Response(`Hello ${user.name}`));
}
```

Pass every response through `login.respond`, or the refreshed session is lost.
Read the secrets from `<NAME>_FILE` too, as for Rust.

## 4. Check that it works

Run the app as the piquel-dev-setup skill describes. Then ask the person to
open the app, sign in with their passkey and approve the consent page. They
should land back on the app, signed in.

## Going further

- An action that needs a fresh passkey: https://docs.piquel.fr/user/apps/step-up.html
- Ending the app's sessions when the user signs out of piquel.fr:
  https://docs.piquel.fr/user/apps/back-channel-logout.html

If the sign-in fails, use the piquel-debug-sign-in skill.
