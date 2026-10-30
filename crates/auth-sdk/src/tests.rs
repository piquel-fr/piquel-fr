//! The shared vectors in `tests/sdk-vectors`, and key cache fetch behavior.

use super::*;
use crate::{client::PendingLogin, http::Http};
use ::axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use piquel_common::protocol::{
    challenge::BearerChallenge, claims::AccessTokenClaims, jwt::TokenType, metadata::ServerMetadata,
};
use serde_json::Value;
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use url::Url;

/// A clock tests move by hand.
#[derive(Clone)]
pub(crate) struct ManualClock(Arc<Mutex<DateTime<Utc>>>);

impl ManualClock {
    /// A clock showing `timestamp`.
    pub(crate) fn at(timestamp: i64) -> Self {
        Self(Arc::new(Mutex::new(
            DateTime::from_timestamp(timestamp, 0).expect("test time"),
        )))
    }

    /// Moves the clock forward.
    pub(crate) fn advance(&self, seconds: i64) {
        *self.0.lock().expect("clock lock") += TimeDelta::seconds(seconds);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().expect("clock lock")
    }
}

/// One vector file.
pub(crate) struct Case {
    /// File name, for assertion messages.
    pub(crate) name: String,
    /// The parsed case.
    pub(crate) json: Value,
}

impl Case {
    /// Every case of `category`, in file name order.
    pub(crate) fn all(category: &str) -> Vec<Self> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/sdk-vectors")
            .join(category);
        let mut cases: Vec<_> = fs::read_dir(directory)
            .expect("read vector category")
            .map(|entry| entry.expect("vector entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|path| Self {
                name: path.display().to_string(),
                json: serde_json::from_slice(&fs::read(&path).expect("read vector"))
                    .expect("parse vector"),
            })
            .collect();
        cases.sort_by(|left, right| left.name.cmp(&right.name));
        assert!(!cases.is_empty(), "no {category} vectors");
        cases
    }

    /// An input field.
    pub(crate) fn input(&self, field: &str) -> &Value {
        &self.json["input"][field]
    }

    /// An input string.
    pub(crate) fn text(&self, field: &str) -> &str {
        self.input(field).as_str().expect("string input")
    }

    /// The case's clock.
    pub(crate) fn clock(&self) -> ManualClock {
        ManualClock::at(self.json["now"].as_i64().expect("now"))
    }

    /// Compares a result with the expected value or error code.
    fn assert<T: serde::Serialize>(&self, result: Result<T, SdkError>) {
        let expected = &self.json["expected"];
        match result {
            Ok(value) => assert_eq!(
                serde_json::to_value(value).expect("serialize result"),
                expected["ok"],
                "{}",
                self.name
            ),
            Err(code) => assert_eq!(
                serde_json::to_value(code).expect("serialize code"),
                expected["error"],
                "{}",
                self.name
            ),
        }
    }
}

/// The metadata of the valid discovery vector.
pub(crate) fn metadata() -> ServerMetadata {
    let discovery = Case::all("discovery")
        .into_iter()
        .find(|case| case.name.ends_with("/valid.json"))
        .expect("valid discovery vector");
    serde_json::from_value(discovery.input("document").clone()).expect("metadata")
}

/// The issuer every token case is validated against, with the case's keys and clock.
pub(crate) fn issuer(case: &Case) -> Issuer {
    issuer_with(case, metadata())
}

/// The issuer with `metadata`, and the case's keys and clock.
fn issuer_with(case: &Case, metadata: ServerMetadata) -> Issuer {
    let keys = KeySet::parse(&serde_json::to_vec(case.input("jwks")).expect("JWKS"))
        .expect("token vectors use valid key sets");
    Issuer::with_keys(
        metadata,
        KeyCache::fixed(keys),
        Http::default_client().expect("HTTP client"),
        Arc::new(case.clock()),
    )
}

/// Metadata is accepted only for the configured issuer and with PKCE.
#[test]
fn discovery_vectors() {
    for case in Case::all("discovery") {
        let document = serde_json::to_vec(case.input("document")).expect("document");
        case.assert(
            Issuer::check_metadata(case.text("issuer"), &document).map_err(|error| error.code()),
        );
    }
}

/// Key sets keep exactly the usable keys.
#[test]
fn jwks_vectors() {
    for case in Case::all("jwks") {
        let document = serde_json::to_vec(case.input("jwks")).expect("JWKS");
        case.assert(
            KeySet::parse(&document)
                .map(|keys| serde_json::json!({ "kids": keys.kids().collect::<Vec<_>>() }))
                .map_err(|error| error.code()),
        );
    }
}

/// Access, ID and logout tokens pass or fail exactly as the vectors say.
#[tokio::test]
async fn token_vectors() {
    for case in Case::all("tokens") {
        let issuer = issuer(&case);
        let token = case.text("token");
        let audience = case.text("audience");
        match case.text("kind") {
            "access" => {
                let resource = Resource::new(audience).expect("vector resource");
                match issuer.resource(resource).validate::<Scopes>(token).await {
                    Ok(_) => case.assert::<AccessTokenClaims>(Ok(issuer
                        .decode(token, TokenType::Access, audience)
                        .await
                        .expect("decode a token that validated"))),
                    Err(error) => case.assert::<()>(Err(error.code())),
                }
            }
            "id" => {
                let max_age = case
                    .input("max_age")
                    .as_u64()
                    .map(|age| u32::try_from(age).expect("max_age fits u32"));
                let result = issuer
                    .id_token(
                        token,
                        &audience.parse::<ClientId>().expect("client ID"),
                        Some(case.text("nonce")),
                        max_age,
                    )
                    .await;
                case.assert(
                    result
                        .map(|token| token.claims().clone())
                        .map_err(|error| error.code()),
                );
            }
            "logout" => {
                let client = issuer.client(ClientConfig {
                    client_id: audience.parse::<ClientId>().expect("client ID"),
                    credentials: Credentials::None,
                    redirect_uri: "https://client.example.com/callback".parse().expect("URL"),
                });
                case.assert(
                    client
                        .logout_token(token)
                        .await
                        .map(|token| token.claims().clone())
                        .map_err(|error| error.code()),
                );
            }
            kind => panic!("unknown token kind {kind} in {}", case.name),
        }
    }
}

/// Challenges format to exactly the vector's header and parse back.
#[test]
fn challenge_vectors() {
    for case in Case::all("challenges") {
        let expected = &case.json["expected"]["ok"];
        if let Some(header) = case.input("header").as_str() {
            let challenge: Option<BearerChallenge> = header.parse().ok();
            assert_eq!(
                serde_json::json!({ "challenge": challenge }),
                *expected,
                "{}",
                case.name
            );
            continue;
        }
        let challenge: BearerChallenge =
            serde_json::from_value(case.input("challenge").clone()).expect("vector challenge");
        let header = expected["header"].as_str().expect("header");
        assert_eq!(challenge.to_string(), header, "{}", case.name);
        assert_eq!(
            u64::from(challenge.status()),
            expected["status"],
            "{}",
            case.name
        );
        assert_eq!(
            header.parse::<BearerChallenge>().as_ref(),
            Ok(&challenge),
            "{}",
            case.name
        );
    }
}

/// The step-up vector's challenge parses back into its requirement, and a token
/// failing that requirement answers with the same header.
#[test]
fn step_up_challenge_round_trips() {
    let case = Case::all("challenges")
        .into_iter()
        .find(|case| case.name.ends_with("insufficient-user-authentication.json"))
        .expect("step-up vector");
    let header = case.json["expected"]["ok"]["header"]
        .as_str()
        .expect("header");
    let parsed: BearerChallenge = header.parse().expect("challenge");
    assert_eq!(parsed.step_up, StepUpRequirement::passkey_within(300));
    let answer = TokenError::InsufficientUserAuthentication(parsed.step_up)
        .challenge()
        .expect("a challenge");
    let answer = BearerChallenge {
        error_description: parsed.error_description.clone(),
        resource_metadata: parsed.resource_metadata.clone(),
        ..answer
    };
    assert_eq!(answer.to_string(), header);
}

/// A token's authentication meets a requirement as auth judges it: `phr` meets a
/// social requirement, and `auth_time` gets the leeway.
#[test]
fn authentication_requirements_follow_auth() {
    let now = Utc::now();
    let token = |acr, age: i64| AccessToken {
        subject: Subject::User(UserId::new()),
        client_id: "notes-web".parse::<ClientId>().expect("client ID"),
        scopes: Scopes::default(),
        token_id: TokenId::new(),
        session_id: None,
        auth_time: Some(now - TimeDelta::seconds(age)),
        amr: Vec::new(),
        acr: Some(acr),
        actor: None,
        confirmation: None,
        profile: ProfileClaims::default(),
        issued_at: now,
        expires_at: now,
        extra: (),
    };
    let social = StepUpRequirement {
        acr: Some(Acr::Social),
        max_age: None,
    };
    assert!(
        token(Acr::PhishingResistant, 0)
            .require_authentication(social, now)
            .is_ok()
    );
    let recent = StepUpRequirement::passkey_within(300);
    assert!(
        token(Acr::PhishingResistant, 330)
            .require_authentication(recent, now)
            .is_ok()
    );
    assert!(matches!(
        token(Acr::PhishingResistant, 331).require_authentication(recent, now),
        Err(TokenError::InsufficientUserAuthentication(requirement)) if requirement == recent
    ));
    assert!(
        token(Acr::Social, 0)
            .require_authentication(recent, now)
            .is_err()
    );
}

/// Callbacks are checked before any code exchange.
#[test]
fn callback_vectors() {
    for case in Case::all("callbacks") {
        let pending: PendingLogin = serde_json::from_value(serde_json::json!({
            "issuer": case.text("issuer"),
            "client_id": "notes-web",
            "state": case.text("state"),
            "nonce": "unused",
            "verifier": "unused",
            "redirect_uri": "https://client.example.com/callback",
            "step_up": {},
        }))
        .expect("pending login");
        let parameters: CallbackParams =
            serde_json::from_value(case.input("parameters").clone()).expect("callback parameters");
        let advertised = case
            .input("authorization_response_iss_parameter_supported")
            .as_bool()
            .expect("flag");
        case.assert(
            pending
                .check(&parameters, advertised)
                .map(|code| serde_json::json!({ "code": code }))
                .map_err(|error| error.code()),
        );
    }
}

/// A local key endpoint whose responses tests switch between, counting requests.
struct KeyServer {
    /// The JWKS URL.
    url: Url,
    /// Requests served so far.
    requests: Arc<AtomicUsize>,
    /// Index into the served documents; past the end, the server fails.
    phase: Arc<AtomicUsize>,
}

impl KeyServer {
    /// Serves `documents` in turn as `phase` advances.
    async fn start(documents: Vec<Value>) -> Self {
        let requests = Arc::new(AtomicUsize::new(0));
        let phase = Arc::new(AtomicUsize::new(0));
        let (served, current) = (requests.clone(), phase.clone());
        let documents = Arc::new(documents);
        let router = Router::new().route(
            "/jwks",
            get(move || {
                served.fetch_add(1, Ordering::SeqCst);
                let document = documents.get(current.load(Ordering::SeqCst)).cloned();
                async move {
                    document
                        .map(::axum::Json)
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
                }
            }),
        );
        let address = serve(router).await;
        Self {
            url: format!("http://{address}/jwks").parse().expect("JWKS URL"),
            requests,
            phase,
        }
    }

    /// Requests served so far.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// Serves `router` on a local port, returning its address.
pub(crate) async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local server");
    let address = listener.local_addr().expect("local server address");
    tokio::spawn(async move { ::axum::serve(listener, router).await });
    address
}

/// A token from a vector file.
pub(crate) fn vector_token(name: &str) -> String {
    Case::all("tokens")
        .into_iter()
        .find(|case| case.name.ends_with(&format!("/{name}.json")))
        .expect("token vector")
        .text("token")
        .to_owned()
}

/// Verifies `token`'s signature with `keys`.
async fn verify(keys: &KeyCache, token: &str) -> Result<(), TokenError> {
    let jws = Jws::parse(token)?;
    keys.verify(
        &jws,
        jws.require_algorithm(&[protocol::jwt::Algorithm::Rs256])?,
    )
    .await
}

/// Concurrent first uses share one fetch, a new `kid` triggers exactly one refetch, a
/// second unknown `kid` within 30 seconds triggers none, and a failed refresh keeps the
/// old keys.
#[tokio::test]
async fn key_rotation_refetches_once_and_survives_outages() {
    let jwks = |name: &str| {
        Case::all("jwks")
            .into_iter()
            .find(|case| case.name.ends_with(&format!("/{name}.json")))
            .expect("JWKS vector")
            .input("jwks")
            .clone()
    };
    let server = KeyServer::start(vec![jwks("rotation-before"), jwks("rotation-during")]).await;
    let clock = ManualClock::at(1_767_225_600);
    let keys = KeyCache::with_clock(server.url.clone(), reqwest::Client::new(), clock.clone());
    let old = vector_token("access-valid");
    let new = vector_token("access-new-key");
    // The same token with a header naming a key no set has.
    let (_, rest) = old.split_once('.').expect("compact token");
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"key-2027","typ":"at+jwt"}"#);
    let unknown = format!("{header}.{rest}");

    let mut first = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let (keys, old) = (keys.clone(), old.clone());
        first.spawn(async move { verify(&keys, &old).await });
    }
    while let Some(result) = first.join_next().await {
        result.expect("task").expect("old key before rotation");
    }
    assert_eq!(
        server.requests(),
        1,
        "concurrent first uses share one fetch"
    );

    server.phase.store(1, Ordering::SeqCst);
    clock.advance(31);
    verify(&keys, &new)
        .await
        .expect("new key after one refetch");
    assert_eq!(server.requests(), 2, "a new kid refetches once");

    clock.advance(9);
    assert!(matches!(
        verify(&keys, &unknown).await,
        Err(TokenError::UnknownKey(Some(_)))
    ));
    verify(&keys, &new).await.expect("fresh keys need no fetch");
    assert_eq!(server.requests(), 2, "no refetch within 30 seconds");

    server.phase.store(2, Ordering::SeqCst);
    clock.advance(2 * 3600);
    verify(&keys, &old)
        .await
        .expect("stale keys survive a failed refresh");
    assert_eq!(server.requests(), 3);
    clock.advance(31);
    assert!(matches!(
        verify(&keys, &unknown).await,
        Err(TokenError::Keys(KeyError::Network(_)))
    ));
    assert_eq!(server.requests(), 4);
    // Until a fetch succeeds, a missing key is unavailable rather than unknown.
    assert!(matches!(
        verify(&keys, &unknown).await,
        Err(TokenError::Keys(KeyError::Unavailable))
    ));
    assert_eq!(server.requests(), 4);
}

/// The public client `id` of the vectors' issuer, which pushes its authorization
/// requests to `pushed` when given.
fn login_client(id: &str, pushed: Option<Url>) -> Client {
    let mut metadata = metadata();
    metadata.pushed_authorization_request_endpoint = pushed;
    issuer_with(&Case::all("tokens").remove(0), metadata).client(ClientConfig {
        client_id: id.parse::<ClientId>().expect("client ID"),
        credentials: Credentials::None,
        redirect_uri: "https://client.example.com/callback".parse().expect("URL"),
    })
}

/// A pushed authorization endpoint answering every request with `status` and `body`,
/// keeping the form it last received.
struct PushEndpoint {
    /// The endpoint's URL.
    url: Url,
    /// The last form received.
    received: Arc<Mutex<Vec<(String, String)>>>,
}

impl PushEndpoint {
    /// Serves the endpoint on a local port.
    async fn start(status: StatusCode, body: Value) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let kept = received.clone();
        let router = Router::new().route(
            "/par",
            post(
                move |::axum::Form(form): ::axum::Form<Vec<(String, String)>>| {
                    *kept.lock().expect("form lock") = form;
                    let body = body.clone();
                    async move { (status, ::axum::Json(body)) }
                },
            ),
        );
        let address = serve(router).await;
        Self {
            url: format!("http://{address}/par").parse().expect("URL"),
            received,
        }
    }

    /// The value of `name` in the last form received.
    fn field(&self, name: &str) -> Option<String> {
        self.received
            .lock()
            .expect("form lock")
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
    }
}

/// With a pushed authorization endpoint advertised, the request goes there, with the
/// public client's `client_id`, and the browser gets only `client_id` and the
/// `request_uri`.
#[tokio::test]
async fn authorize_pushes_when_advertised() {
    let request_uri = "urn:ietf:params:oauth:request_uri:abc";
    let endpoint = PushEndpoint::start(
        StatusCode::CREATED,
        serde_json::json!({ "request_uri": request_uri, "expires_in": 60 }),
    )
    .await;
    let client = login_client("notes-web", Some(endpoint.url.clone()));
    let request = AuthorizeRequest {
        step_up: StepUpRequirement::passkey_within(300),
        ..AuthorizeRequest::default()
    };
    let (url, pending) = client.authorize(&request).await.expect("authorize");
    assert_eq!(endpoint.field("client_id").as_deref(), Some("notes-web"));
    assert_eq!(endpoint.field("state").as_deref(), Some(pending.state()));
    // The step-up requirement travels in the pushed request, not the URL.
    assert_eq!(endpoint.field("acr_values").as_deref(), Some("phr"));
    assert_eq!(endpoint.field("max_age").as_deref(), Some("300"));
    assert_eq!(url.path(), metadata().authorization_endpoint.path());
    let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query,
        [
            ("client_id".to_owned(), "notes-web".to_owned()),
            ("request_uri".to_owned(), request_uri.to_owned()),
        ]
    );
}

/// A pushed request auth refuses fails the login with auth's OAuth error.
#[tokio::test]
async fn refused_pushes_keep_the_oauth_error() {
    let endpoint = PushEndpoint::start(
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": "invalid_scope" }),
    )
    .await;
    let refused = login_client("notes-web", Some(endpoint.url))
        .authorize(&AuthorizeRequest::default())
        .await
        .expect_err("refused");
    assert_eq!(
        refused.code(),
        SdkError::category(protocol::sdk::ErrorCategory::OAuth)
    );
    assert!(matches!(
        refused,
        LoginError::Push(OAuthError::Rejected { response, .. })
            if response.error == protocol::oauth::ErrorCode::InvalidScope
    ));
}

/// A pending login completes only with the client and issuer that started it, before
/// anything is sent anywhere.
#[tokio::test]
async fn pending_logins_complete_only_with_their_client() {
    let (_, pending) = login_client("notes-web", None)
        .authorize(&AuthorizeRequest::default())
        .await
        .expect("authorize");
    let callback = CallbackParams {
        code: Some("code".into()),
        state: Some(pending.state().into()),
        iss: Some(metadata().issuer),
        ..CallbackParams::default()
    };
    assert!(matches!(
        login_client("another-client", None)
            .complete(pending, &callback)
            .await,
        Err(LoginError::ForeignLogin)
    ));
}

/// A fetch cancelled mid-request still counts as failed: until a fetch succeeds, a
/// missing key is unavailable rather than unknown.
#[tokio::test]
async fn cancelled_fetches_leave_keys_unavailable() {
    // Accepts connections but never answers.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/jwks", silent.local_addr().expect("address"));
    let keys = KeyCache::with_clock(
        url.parse().expect("URL"),
        reqwest::Client::new(),
        ManualClock::at(1_767_225_600),
    );
    let token = vector_token("access-valid");
    let cancelled =
        tokio::time::timeout(std::time::Duration::from_millis(100), verify(&keys, &token)).await;
    assert!(cancelled.is_err(), "the fetch never completes");
    assert!(matches!(
        verify(&keys, &token).await,
        Err(TokenError::Keys(KeyError::Unavailable))
    ));
}
