//! A small notes service using both halves of the axum integration: an API that
//! accepts access tokens for `notes-api`, and a page that signs users in.
//!
//! Register a client with auth, then run:
//!
//! ```sh
//! NOTES_CLIENT_ID=notes-web NOTES_CLIENT_SECRET=… \
//! NOTES_REDIRECT_URI=https://notes.example.com/auth/callback \
//! cargo run -p piquel-auth --features axum --example notes
//! ```

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use piquel_auth::{
    ClientConfig, ClientId, Credentials, Issuer, Resource,
    axum::{BearerLayer, LoginRoutes, MemorySessions, Scoped, SignedIn},
};
use std::{
    env,
    error::Error,
    sync::{Arc, Mutex, PoisonError},
};

piquel_auth::scopes! {
    /// Scopes of the notes API.
    pub mod notes {
        /// Read every note.
        Read = "notes:read",
        /// Add notes.
        Write = "notes:write",
    }
}

/// The notes, in memory.
type Notes = Arc<Mutex<Vec<String>>>;

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

/// `GET /`: signs the user in first.
async fn home(user: SignedIn) -> String {
    format!("Hello {}", user.name())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let issuer = env::var("PIQUEL_ISSUER").unwrap_or_else(|_| "https://auth.piquel.fr".into());
    let issuer = Issuer::discover(&issuer).await?;

    let api = Router::new()
        .route("/notes", get(list).post(create))
        .with_state(Notes::default())
        .layer(BearerLayer::new(
            issuer.resource(Resource::new("notes-api")?),
        ));

    let config = ClientConfig {
        client_id: ClientId::new(env::var("NOTES_CLIENT_ID")?),
        credentials: Credentials::Secret(env::var("NOTES_CLIENT_SECRET")?.into()),
        redirect_uri: env::var("NOTES_REDIRECT_URI")?.parse()?,
    };
    let auth = LoginRoutes::new(issuer.client(config), MemorySessions::default())
        .scopes("profile".parse()?);

    let app = Router::new()
        .route("/", get(home))
        .nest("/auth", auth.router())
        .layer(auth.layer())
        .nest("/api", api);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
