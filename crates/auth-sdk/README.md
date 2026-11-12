# sourceorigin-auth

The Rust SDK for [Origin Auth](https://auth.sourceorigin.dev). It signs users in to
your app with their Origin Account, and validates the access tokens auth issues,
with your API's scopes declared as types.

## Install

```console
cargo add sourceorigin-auth --features axum
```

The `axum` feature adds extractors, a bearer layer and the login routes for
[axum](https://docs.rs/axum) 0.8. Without it, the SDK works with any framework. It
needs Rust 1.88 or newer, and a C compiler for its cryptography,
[aws-lc-rs](https://docs.rs/aws-lc-rs).

## Sign users in

With the `axum` feature, `LoginRoutes` serves the login routes under `/auth` and
keeps each user's session in a sealed cookie, so your app stores nothing:

```rust,no_run
use axum::{Router, routing::get};
use sourceorigin_auth::axum::{CookieKey, LoginRoutes, SignedIn};
use sourceorigin_auth::{ClientConfig, Credentials, Issuer};

async fn home(user: SignedIn) -> String {
    format!("Hello {}", user.name())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Issuer::discover("https://auth.sourceorigin.dev").await?;
    let config = ClientConfig {
        client_id: "notes-web".parse()?,
        credentials: Credentials::Secret(std::env::var("CLIENT_SECRET")?.into()),
        redirect_uri: "https://notes.example/auth/callback".parse()?,
    };
    // `openssl rand -base64 32`, the same on every replica.
    let key = CookieKey::parse(&std::env::var("COOKIE_KEY")?)?;
    let auth = LoginRoutes::new(issuer.client(config), key)?.scopes("profile".parse()?);
    let app = Router::new()
        .route("/", get(home))
        .nest("/auth", auth.router())
        .layer(auth.layer());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

[Signing in with Rust](https://docs.sourceorigin.dev/user/apps/sign-in-rust.html)
explains it, and what to register first.

## APIs

`Issuer::resource` validates the access tokens an API receives, and `scopes!`
declares its scopes as types, so a misspelled scope doesn't compile: see
[protecting an API](https://docs.sourceorigin.dev/user/apps/protect-an-api.html).

## Learn more

- [The API documentation](https://docs.rs/sourceorigin-auth)
- [How sign-in works](https://docs.sourceorigin.dev/user/apps/how-sign-in-works.html)
- [Step-up authentication](https://docs.sourceorigin.dev/user/apps/step-up.html)
- [Back-channel logout](https://docs.sourceorigin.dev/user/apps/back-channel-logout.html)
- [Changes in each release](https://github.com/sourceorigin-dev/sourceorigin/releases)
- [The SDK's design](https://docs.sourceorigin.dev/dev/architecture/sdk.html), to change
  it

## License

[Apache-2.0](LICENSE-APACHE).
