//! Federation protocol, browser-binding and transactional identity policy tests.

mod callback;
mod linking;
mod protocols;
mod sign_in;
mod signup;

use super::{
    providers::{IdentityStrategy, ProviderEndpoints},
    *,
};
use crate::{
    account::AccountApplication,
    tests::{pending_sign_in, unusable_passkey},
};
use axum::{
    Json,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
    routing::post,
};
use piquel_common::{Handle, PasskeyId};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseTransaction, InsertUser, InsertVerifiedEmail};
use tower::ServiceExt;

/// Isolated database fixture with replaceable provider endpoints and unique subjects.
struct TestApp {
    /// Federation state whose back-channel requests use a local HTTP fixture.
    app: FederationApplication,
    /// Provider mock server, stopped when the fixture is dropped.
    task: tokio::task::JoinHandle<()>,
    /// Temporary provider secret deleted with the fixture.
    secret_file: std::path::PathBuf,
    /// Unique numeric subject returned by this fixture’s provider.
    subject: String,
    /// Email settings that send, so imported addresses get their links.
    email: crate::config::EmailConfig,
}
impl Drop for TestApp {
    /// Stops the fixture server and attempts to remove its temporary secret.
    fn drop(&mut self) {
        self.task.abort();
        if let Err(error) = std::fs::remove_file(&self.secret_file) {
            tracing::warn!(%error, "could not remove federation fixture secret");
        }
    }
}
impl TestApp {
    /// The federation routes and the shared settings, as the public listener
    /// serves them.
    fn routes(&self) -> axum::Router {
        self.app
            .clone()
            .routes()
            .merge(AccountApplication::new(self.app.database.clone()).routes())
    }
    /// Creates a provider fixture with no verified contact address.
    async fn new() -> Self {
        Self::with_email(None).await
    }
    /// Creates unique provider evidence with an optional verified primary address.
    async fn with_email(email: Option<&str>) -> Self {
        let database = crate::tests::Replicas::database().await;
        let subject = u64::from_be_bytes(
            piquel_crypto::Secret::generate()
                .expect("random")
                .as_bytes()[..8]
                .try_into()
                .expect("eight bytes"),
        )
        .max(1);
        let emails = email.map_or_else(
            || serde_json::json!([]),
            |email| serde_json::json!([{"email":email,"primary":true,"verified":true}]),
        );
        let mock = Router::new()
            .route(
                "/token",
                post(|| async { Json(serde_json::json!({"access_token":"mock-token"})) }),
            )
            .route(
                "/user",
                get(move || async move {
                    Json(serde_json::json!({"id":subject,"name":"Social User","login":"social"}))
                }),
            )
            .route(
                "/emails",
                get(move || {
                    let emails = emails.clone();
                    async move { Json(emails) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let base = format!("http://{}", listener.local_addr().expect("mock address"));
        let task = tokio::spawn(async move {
            axum::serve(listener, mock).await.expect("mock server");
        });
        let secret_file =
            std::env::temp_dir().join(format!("piquel-federation-test-{}", TokenId::new()));
        std::fs::write(&secret_file, "test-secret").expect("mock provider secret");
        let config = ProviderConfig::test(&secret_file);
        let mut app = FederationApplication::new(
            database,
            &FederationConfig {
                origin: "https://auth.piquel.fr/"
                    .parse::<piquel_common::config::Origin>()
                    .expect("origin"),
                providers: BTreeMap::from([(Provider::GitHub, config)]),
            },
        )
        .expect("federation");
        let endpoints = app
            .endpoints
            .get_mut(&Provider::GitHub)
            .expect("GitHub facts");
        endpoints.token = format!("{base}/token");
        match &mut endpoints.identity {
            IdentityStrategy::GitHub(protocol) => {
                protocol.user = format!("{base}/user");
                protocol.emails = format!("{base}/emails");
            }
            IdentityStrategy::Google(_) => panic!("GitHub must use OAuth profile fetching"),
        }
        Self {
            app,
            task,
            secret_file,
            subject: subject.to_string(),
            email: crate::config::EmailConfig::test(
                &"https://auth.piquel.fr/".parse().expect("origin"),
                true,
            ),
        }
    }
    /// Runs a complete GitHub authorization start and bound callback.
    async fn callback(&self) -> Response {
        self.callback_from(None).await
    }
    /// Starts a GitHub sign-in returning to `return_to`, as the sign-in page does,
    /// and returns the provider's `state` and the browser's flow cookie pair.
    async fn start(&self, return_to: &str) -> (String, String) {
        let (url, FlowCookie(Flow::Started(browser))) = self
            .app
            .start_sign_in(Provider::GitHub, return_to)
            .await
            .expect("start")
        else {
            unreachable!("starting a sign-in sets the flow's cookie")
        };
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .expect("state")
            .1
            .into_owned();
        let cookie = format!(
            "{}={}",
            BrowserCookie::Federation.as_str(),
            browser.encoded()
        );
        (state, cookie)
    }
    /// Runs [`Self::callback`] in a browser that may hold a `session` cookie pair.
    async fn callback_from(&self, session: Option<&str>) -> Response {
        let (state, mut cookie) = self.start(DEFAULT_RETURN_TO).await;
        if let Some(session) = session {
            cookie = format!("{cookie}; {session}");
        }
        self.routes()
            .oneshot(TestApp::request(
                Method::GET,
                &format!("/login/github/callback?state={state}&code=mock-code"),
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("callback")
    }
    /// Creates a unique account with optional verified email and passkey.
    async fn user(&self, email: Option<&str>, with_key: bool) -> UserId {
        let id = UserId::new();
        let mut tx = self.app.database.begin().await.expect("transaction");
        tx.users()
            .insert(&InsertUser {
                id,
                handle: Handle::parse(&format!("fed-{}", &TokenId::new().to_string()[24..]))
                    .expect("handle"),
                display_name: "Federation Test".into(),
            })
            .await
            .expect("user");
        if let Some(email) = email {
            tx.emails()
                .insert_verified(&InsertVerifiedEmail {
                    id: piquel_common::EmailId::new(),
                    user_id: id,
                    normalized_email: email.into(),
                    is_primary: true,
                    verified_at: Utc::now(),
                })
                .await
                .expect("email");
        }
        if with_key {
            self.key(&mut tx, id).await;
        }
        tx.commit().await.expect("commit");
        id
    }
    /// Adds passkey-presence evidence; ceremony cryptography is covered by passkey tests.
    async fn key(&self, tx: &mut DatabaseTransaction<'_>, user_id: UserId) {
        // Federation only checks key presence; cryptographic ceremony coverage lives in passkey tests.
        tx.passkeys()
            .insert(&unusable_passkey(user_id))
            .await
            .expect("key");
    }
    /// Stores browser-bound evidence optionally targeting an existing account.
    async fn pending(
        &self,
        owner: Option<UserId>,
        email: Option<&str>,
    ) -> (PendingFederation, HeaderMap) {
        self.pending_from(|pending| PendingFederation {
            email: email.map(str::to_owned),
            link_user_id: owner,
            ..pending
        })
        .await
    }
    /// Stores the browser-bound evidence `change` makes of a new GitHub signup's.
    async fn pending_from(
        &self,
        change: impl FnOnce(PendingFederation) -> PendingFederation,
    ) -> (PendingFederation, HeaderMap) {
        let secret = Secret::generate().expect("browser secret");
        let pending = change(pending_sign_in(&secret));
        self.app
            .database
            .federation()
            .insert_pending(&pending)
            .await
            .expect("pending identity");
        let cookie = format!(
            "{}={}",
            BrowserCookie::FederationPending.as_str(),
            secret.encoded()
        );
        (pending, Self::cookies(&cookie))
    }
    /// Creates a social browser session, optionally confirmed with a passkey now.
    async fn session(&self, user_id: UserId, confirmed: bool) -> (SessionId, String) {
        let mut tx = self.app.database.begin().await.expect("transaction");
        let cookie = security::Session::create(
            &mut tx,
            security::RequestContext::TEST,
            user_id,
            AuthenticationMethod::Federation.into(),
        )
        .await
        .expect("session");
        let raw = format!("{}={}", BrowserCookie::Session.as_str(), cookie.encoded());
        tx.commit().await.expect("commit");
        let session = security::Session::required(&self.app.database, &Self::cookies(&raw))
            .await
            .expect("active session");
        if confirmed {
            self.app
                .database
                .sessions()
                .confirm_passkey(session.id, PasskeyId::new(), chrono::Utc::now())
                .await
                .expect("confirm");
        }
        (session.id, raw)
    }
    /// The headers of a browser sending the `cookie` pairs.
    fn cookies(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie).expect("cookie"),
        );
        headers
    }
    /// Builds a JSON HTTP request with an optional browser-cookie header.
    fn request(
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: &serde_json::Value,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .extension(crate::security::RequestContext::TEST)
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request.body(Body::from(body.to_string())).expect("request")
    }
}
