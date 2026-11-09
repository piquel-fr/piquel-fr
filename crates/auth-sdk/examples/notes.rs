//! A small notes service using both halves of the axum integration: an API that
//! accepts access tokens for `notes-api`, and a page that signs users in and refuses
//! the sessions a back-channel logout ended.
//!
//! Register a client with auth, then run:
//!
//! ```sh
//! NOTES_CLIENT_ID=notes-web NOTES_CLIENT_SECRET=… \
//! NOTES_REDIRECT_URI=https://notes.example.com/auth/callback \
//! NOTES_COOKIE_KEY="$(openssl rand -base64 32)" \
//! cargo run -p piquel-auth --features axum --example notes
//! ```
//!
//! The `ANCHOR` comments mark the parts `docs/user/apps/sign-in-rust.md` and
//! `docs/user/apps/protect-an-api.md` show.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use piquel_auth::{
    ClientConfig, Credentials, Issuer, LogoutScope, Resource, SessionId,
    axum::{BearerLayer, CookieKey, LoginRoutes, Scoped, SignedIn},
};
use std::{
    collections::HashSet,
    convert::Infallible,
    env,
    error::Error,
    sync::{Arc, Mutex, PoisonError},
};

// ANCHOR: scopes
piquel_auth::scopes! {
    /// Scopes of the notes API.
    pub mod notes {
        /// Read every note.
        Read = "notes:read",
        /// Add notes.
        Write = "notes:write",
    }
}
// ANCHOR_END: scopes

/// The notes, in memory.
type Notes = Arc<Mutex<Vec<String>>>;

// ANCHOR: handlers
/// `GET /api/notes`: needs `notes:read`.
async fn list(State(notes): State<Notes>, _: Scoped<notes::Read>) -> Json<Vec<String>> {
    Json(notes.lock().unwrap_or_else(PoisonError::into_inner).clone())
}

/// `POST /api/notes`: needs `notes:read` and `notes:write`.
async fn create(
    State(notes): State<Notes>,
    _: Scoped<(notes::Read, notes::Write)>,
    Json(note): Json<String>,
) -> StatusCode {
    notes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(note);
    StatusCode::CREATED
}
// ANCHOR_END: handlers

// ANCHOR: home
/// Auth sessions that back-channel logouts ended. Kept in the app's database in
/// practice, so every replica sees it.
type Ended = Arc<Mutex<HashSet<SessionId>>>;

/// `GET /`: signs the user in first, and refuses a session auth ended.
async fn home(State(ended): State<Ended>, user: SignedIn) -> Result<String, StatusCode> {
    let ended = ended.lock().unwrap_or_else(PoisonError::into_inner);
    if user.sid().is_some_and(|sid| ended.contains(&sid)) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(format!("Hello {}", user.name()))
}
// ANCHOR_END: home

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ANCHOR: issuer
    let issuer = env::var("PIQUEL_ISSUER").unwrap_or_else(|_| "https://auth.piquel.fr".into());
    let issuer = Issuer::discover(&issuer).await?;
    // ANCHOR_END: issuer

    // ANCHOR: api
    let api = Router::new()
        .route("/notes", get(list).post(create))
        .with_state(Notes::default())
        .layer(BearerLayer::new(
            issuer.resource(Resource::new("notes-api")?),
        ));
    // ANCHOR_END: api

    // ANCHOR: login
    let config = ClientConfig {
        client_id: env::var("NOTES_CLIENT_ID")?.parse()?,
        credentials: Credentials::Secret(env::var("NOTES_CLIENT_SECRET")?.into()),
        redirect_uri: env::var("NOTES_REDIRECT_URI")?.parse()?,
    };
    // Sessions live in the browser, sealed with this key: every replica uses the same.
    let key = CookieKey::from_base64(&env::var("NOTES_COOKIE_KEY")?)?;
    let auth = LoginRoutes::new(issuer.client(config), key)?.scopes("profile".parse()?);
    // ANCHOR_END: login

    // ANCHOR: backchannel
    let ended = Ended::default();
    let recorded = ended.clone();
    let auth = auth.on_backchannel_logout(move |logout| {
        // Auth's logout tokens always name the session that ended.
        if let LogoutScope::Session(sid) = logout.scope() {
            recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(*sid);
        }
        async { Ok::<_, Infallible>(()) }
    });
    // ANCHOR_END: backchannel

    // ANCHOR: router
    let app = Router::new()
        .route("/", get(home))
        .with_state(ended)
        .nest("/auth", auth.router())
        .layer(auth.layer())
        .nest("/api", api);
    // ANCHOR_END: router
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
