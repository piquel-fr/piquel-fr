//! Two instances of the whole service on one database, as piqueld runs replicas,
//! and the fixtures shared by the applications' tests.

use crate::{
    AuthConfig, ClientRegistry, ClientRegistryError, KeyStore, Operator, Reason,
    account::{AccountService, Owner},
    clients::{ClientSettings, NewClient},
    config::{
        AuditConfig, EmailConfig, FederationConfig, OidcConfig, PasskeyConfig, ProviderConfig,
        TokenDigestKey, TokenDigestKeys,
    },
    passkey::DecoyKey,
    recovery::RecoveryLinks,
    routes,
    security::{BrowserCookie, RequestContext, Session},
};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::Response,
};
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, ClientId, EmailId, Handle, PasskeyId, Provider, SessionId, TokenId,
    UserId,
    clients::{
        AllowedScopes, ClientField, ClientKind, ClientOwner, ClientRegistration, PostLogoutUris,
        RedirectUris, ScopeName,
    },
    config::Origin,
    events::{Actor, RevocationReason},
    protocol::oauth::Scope,
};
use piquel_crypto::{ClientSecret, KeyEncryptionKey, NoteKey, Secret};
use piquel_repository::{
    Database, DatabaseConfig, DatabaseError, DatabaseTransaction, InsertAuthorizationCode,
    InsertPasskey, InsertRefreshFamily, InsertRefreshToken, InsertUser, InsertVerifiedEmail,
    PendingFederation, SessionAuthentication, SessionScope,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tower::ServiceExt;

/// Auth origin of the replicas, and of the fixtures that send requests to them.
pub(crate) const AUTH_ORIGIN: &str = "https://auth.piquel.fr";
/// The key-encryption key of every test that stores signing keys. Tests share one
/// database, so they must all open the keys any of them stored.
const KEY_ENCRYPTION_KEY: &str = "dGVzdHMgc2hhcmUgdGhpcyBrZXktZW5jcnlwdGlvbiE";

/// The key-encryption key tests seal signing keys with.
pub(crate) fn key_encryption_key() -> KeyEncryptionKey {
    KeyEncryptionKey::parse(KEY_ENCRYPTION_KEY).expect("test key-encryption key")
}

/// Two routers built by [`AuthConfig::router`] from one configuration. Each has its
/// own database pool and in-process state, signing keys included, so a test passes
/// only if everything it relies on is shared through PostgreSQL or the configuration.
pub(crate) struct Replicas {
    /// The first replica.
    pub a: Router,
    /// The second replica.
    pub b: Router,
}

impl AuthConfig {
    /// One replica of this service on `database`, with its own signing key store,
    /// receiving every request from `peer`.
    pub(crate) async fn test_router(&self, database: Database, peer: SocketAddr) -> Router {
        let keys = KeyStore::new(database.clone(), Arc::clone(&self.key_encryption_key))
            .start()
            .await
            .expect("signing keys");
        self.router(database, &keys)
            .expect("replica")
            .layer(Extension(ConnectInfo(peer)))
    }

    /// The configuration of a test service at `origin`: no providers, email sent, a
    /// random token digest key, and registration without an invitation.
    pub(crate) fn test(origin: &Origin) -> Self {
        Self {
            public_listener: SocketAddr::from(([127, 0, 0, 1], 0)),
            dashboard: None,
            passkey: PasskeyConfig {
                origin: origin.clone(),
                invite_required: false,
                decoy_key: DecoyKey::new(Secret::generate().expect("decoy key")),
            },
            email: EmailConfig::test(origin, true),
            federation: FederationConfig {
                origin: origin.clone(),
                providers: BTreeMap::new(),
            },
            oidc: OidcConfig {
                origin: origin.clone(),
                digest_keys: Arc::new(TokenDigestKeys::new(
                    TokenDigestKey::derive(Secret::generate().expect("random").as_bytes())
                        .expect("digest key"),
                    None,
                )),
            },
            key_encryption_key: Arc::new(key_encryption_key()),
            audit: AuditConfig {
                key: Arc::new(NoteKey::generate("auth.piquel.fr/audit").expect("audit key")),
            },
            trusted_proxies: vec![],
        }
    }
}

impl Replicas {
    /// Builds both replicas of the test service at [`AUTH_ORIGIN`].
    pub(crate) async fn new() -> Self {
        Self::of(&AuthConfig::test(
            &AUTH_ORIGIN.parse().expect("auth origin"),
        ))
        .await
    }

    /// Builds both replicas from `config`. Every request comes from one client
    /// address, unique to this fixture, so the replicas share its rate-limit budget
    /// and no other test's.
    pub(crate) async fn of(config: &AuthConfig) -> Self {
        let peer = Self::peer();
        Self {
            a: config.test_router(Self::database().await, peer).await,
            b: config.test_router(Self::database().await, peer).await,
        }
    }

    /// Builds both replicas from `config`, with GitHub sign-in enabled.
    pub(crate) async fn with_github(mut config: AuthConfig) -> Self {
        let secret = std::env::temp_dir().join(format!("piquel-github-secret-{}", TokenId::new()));
        std::fs::write(&secret, "secret").expect("provider secret");
        config
            .federation
            .providers
            .insert(Provider::GitHub, ProviderConfig::test(&secret));
        // The replicas read the secret as they start.
        let replicas = Self::of(&config).await;
        std::fs::remove_file(&secret).expect("provider secret removed");
        replicas
    }

    /// The admin listener of `config`'s dashboard, for requests from a client
    /// address of its own.
    pub(crate) async fn dashboard(config: &AuthConfig) -> Router {
        let dashboard = config.dashboard.as_ref().expect("a dashboard");
        config
            .admin_router(Self::database().await, dashboard)
            .expect("dashboard")
            .layer(Extension(ConnectInfo(Self::peer())))
    }

    /// A client address unique to the fixture, so its requests spend no other
    /// test's rate-limit budget.
    fn peer() -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128())),
            4321,
        )
    }

    /// Connects a new pool to the migrated test database.
    pub(crate) async fn database() -> Database {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5))
                .expect("database configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        database
    }
}

/// Largest response body [`Browser::call`] and the page tests read.
pub(crate) const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// What a form on one of auth's pages sends: they have `Referrer-Policy: no-referrer`,
/// so the browser sends `Origin: null`.
pub(crate) const OWN_PAGE: &[(&str, &str)] =
    &[("sec-fetch-site", "same-origin"), ("origin", "null")];

/// A browser signed in to a test account, for handler tests.
pub(crate) struct Browser {
    /// The account.
    pub user_id: UserId,
    /// The browser's session.
    pub session_id: SessionId,
    /// The browser's session cookie pair.
    pub cookie: String,
}

impl Browser {
    /// Creates an account and signs a browser in to it with a passkey.
    pub(crate) async fn new_account(database: &Database) -> Self {
        let user_id = UserId::new();
        database
            .users()
            .insert(&InsertUser {
                id: user_id,
                handle: Handle::parse(&format!("browser-{}", &user_id.to_string()[24..]))
                    .expect("handle"),
                display_name: "Browser test".into(),
            })
            .await
            .expect("user");
        Self::sign_in(database, user_id).await
    }

    /// A browser with no session.
    pub(crate) fn signed_out() -> Self {
        Self {
            user_id: UserId::new(),
            session_id: SessionId::new(),
            cookie: String::new(),
        }
    }

    /// Signs another browser in to `user_id` with a passkey, from
    /// [`RequestContext::TEST`].
    pub(crate) async fn sign_in(database: &Database, user_id: UserId) -> Self {
        Self::sign_in_with(database, user_id, AuthenticationMethod::Passkey).await
    }

    /// Signs another browser in to `user_id` with `method`, from
    /// [`RequestContext::TEST`]. Only a passkey sign-in confirms the session.
    pub(crate) async fn sign_in_with(
        database: &Database,
        user_id: UserId,
        method: AuthenticationMethod,
    ) -> Self {
        let mut tx = database.begin().await.expect("transaction");
        let secret = Session::create(&mut tx, RequestContext::TEST, user_id, method.into())
            .await
            .expect("session");
        let session_id = tx
            .sessions()
            .find_active_by_browser_secret(secret.digest().as_bytes())
            .await
            .expect("lookup")
            .expect("session")
            .id;
        tx.commit().await.expect("commit");
        Self {
            user_id,
            session_id,
            cookie: format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded()),
        }
    }

    /// This browser, also holding `cookie` with `value`.
    pub(crate) fn with_cookie(&self, cookie: BrowserCookie, value: &str) -> Self {
        let pair = format!("{}={value}", cookie.as_str());
        Self {
            user_id: self.user_id,
            session_id: self.session_id,
            cookie: if self.cookie.is_empty() {
                pair
            } else {
                format!("{}; {pair}", self.cookie)
            },
        }
    }

    /// Sends a request to `router` as this browser, with the context
    /// `HttpSecurity` would attach, and returns its status and JSON body.
    pub(crate) async fn call(
        &self,
        router: &Router,
        method: Method,
        path: &str,
    ) -> (StatusCode, Value) {
        self.send(router, method, path, None).await
    }

    /// Like [`Self::call`], sending `body`, if any, as JSON.
    pub(crate) async fn send(
        &self,
        router: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = self
            .request(method, path)
            .extension(RequestContext::TEST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .expect("request");
        let response = Self::dispatch(router, request).await;
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// Navigates to `path` on the whole service as this browser, and returns the
    /// whole response.
    pub(crate) async fn visit(&self, router: &Router, path: &str) -> Response {
        let request = self
            .request(Method::GET, path)
            .body(Body::empty())
            .expect("request");
        Self::dispatch(router, request).await
    }

    /// Posts a page's form, `fields`, to `path` on the whole service as this browser,
    /// with `headers` such as the `Sec-Fetch-Site` and `Origin` it sends, and returns
    /// the whole response. The service's security layer attaches the request context.
    pub(crate) async fn submit(
        &self,
        router: &Router,
        path: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Response {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        let mut request = self
            .request(Method::POST, path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        Self::dispatch(router, request.body(Body::from(form)).expect("request")).await
    }

    /// The headers this browser sends: its cookies.
    pub(crate) fn headers(&self) -> HeaderMap {
        let request = self.request(Method::GET, "/");
        request.headers_ref().expect("request headers").clone()
    }

    /// The owner this browser's session cookie shows, found from
    /// [`RequestContext::TEST`] as a server-rendered page finds them.
    pub(crate) async fn owner(&self, database: &Database) -> Owner {
        AccountService::new(database.clone())
            .owner(RequestContext::TEST, &self.headers())
            .await
            .expect("session lookup")
            .expect("signed in")
    }

    /// Registers a client of `kind` calling back to `{origin}/callback`, with
    /// [`ClientSettings::test`]'s settings, for this browser's account, whose
    /// session must be confirmed, as the new-app page does, and returns its ID.
    pub(crate) async fn register_app(
        &self,
        database: &Database,
        kind: ClientKind,
        origin: &str,
    ) -> ClientId {
        let new = NewClient {
            kind,
            settings: ClientSettings::test(origin),
        };
        let (client, _) = AccountService::new(database.clone())
            .create_client(&self.owner(database).await, new)
            .await
            .expect("app registered");
        client.id
    }

    /// A request from this browser, with its session cookie.
    fn request(&self, method: Method, path: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::COOKIE, &self.cookie)
    }

    /// `router`'s response to `request`.
    async fn dispatch(router: &Router, request: Request<Body>) -> Response {
        router.clone().oneshot(request).await.expect("response")
    }
}

/// The value `response` sets the cookie `name` to, and the cookie's attributes.
pub(crate) fn cookie(response: &Response, name: BrowserCookie) -> (&str, &str) {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .find_map(|cookie| cookie.strip_prefix(name.as_str())?.strip_prefix('='))
        .and_then(|cookie| cookie.split_once(';'))
        .unwrap_or_else(|| panic!("{name} is set"))
}

/// `response`'s Content-Security-Policy.
pub(crate) fn policy(response: &Response) -> &str {
    response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .expect("CSP is text")
}

/// `response`'s body, as text.
pub(crate) async fn html(response: Response) -> String {
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("body");
    String::from_utf8(body.to_vec()).expect("UTF-8 page")
}

/// A passkey of `user_id`'s account whose credential no ceremony can use, for the
/// tests that need only an account to have one.
pub(crate) fn unusable_passkey(user_id: UserId) -> InsertPasskey {
    InsertPasskey {
        id: PasskeyId::new(),
        credential_id: TokenId::new().to_string().into_bytes(),
        user_id,
        credential: serde_json::json!({}),
        friendly_name: "Existing key".into(),
    }
}

/// GitHub evidence of a new subject, pending for five minutes in the browser whose
/// cookie holds `browser`: a signup returning to the settings. Callers change the
/// fields they test.
pub(crate) fn pending_sign_in(browser: &Secret) -> PendingFederation {
    PendingFederation {
        id: TokenId::new(),
        browser_digest: browser.digest().as_bytes().to_vec(),
        provider: Provider::GitHub,
        issuer: "https://github.com".into(),
        subject: TokenId::new().to_string(),
        email: None,
        display_name: "Social account".into(),
        return_to: routes::page::settings::HOME.into(),
        link_user_id: None,
        link_session_id: None,
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

/// The value of the query parameter `name` in `url`.
pub(crate) fn parameter(url: &url::Url, name: &str) -> String {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .expect("URL contains expected query parameter")
        .1
        .into_owned()
}

/// Where `response` sends the browser, as its `Location` says it.
pub(crate) fn redirect(response: &Response) -> &str {
    response
        .headers()
        .get(header::LOCATION)
        .expect("response has a Location header")
        .to_str()
        .expect("Location header is valid text")
}

/// The absolute URL in `response`'s `Location`.
pub(crate) fn location(response: &Response) -> url::Url {
    url::Url::parse(redirect(response)).expect("Location header contains an absolute URL")
}

/// The operator client changes made by tests are attributed to, as the `client`
/// command's are.
pub(crate) fn operator() -> Operator {
    Operator::Cli {
        os_user: "test".into(),
        host: "test".into(),
    }
}

/// Recovery links with a key of their own: the routes find a recovery by its
/// token's digest, so they need no key.
pub(crate) fn recovery_links() -> RecoveryLinks {
    RecoveryLinks::new(
        AUTH_ORIGIN.parse().expect("origin"),
        Secret::generate().expect("recovery key"),
        None,
    )
}

/// Why the scenarios recover an account.
pub(crate) fn recovery_reason() -> Reason {
    Reason::parse("Lost every passkey".into()).expect("reason")
}

/// The token of a recovery `link`.
pub(crate) fn recovery_token(link: &url::Url) -> String {
    let fragment = link.fragment().expect("fragment");
    fragment.strip_prefix("token=").expect("token").to_owned()
}

/// Makes `change` with a registry over a transaction of its own, as [`operator`],
/// and commits it if it succeeds.
pub(crate) async fn change<T, E: From<ClientRegistryError>>(
    database: &Database,
    change: impl AsyncFnOnce(&mut ClientRegistry<'_, '_>) -> Result<T, E>,
) -> Result<T, E> {
    let mut tx = database.begin().await.map_err(ClientRegistryError::from)?;
    let value = change(&mut ClientRegistry::new(&mut tx, operator().context())).await?;
    tx.commit().await.map_err(ClientRegistryError::from)?;
    Ok(value)
}

/// Registers `client` as an operator, returning a confidential client's secret.
pub(crate) async fn register(
    database: &Database,
    client: &ClientRegistration,
) -> Result<Option<ClientSecret>, ClientRegistryError> {
    change(database, async |registry| {
        registry.create(ClientOwner::Operator, client, None).await
    })
    .await
}

/// Writes `client` over its stored registration, as an operator.
pub(crate) async fn replace(
    database: &Database,
    client: &ClientRegistration,
) -> Result<Vec<ClientField>, ClientRegistryError> {
    change(database, async |registry| {
        registry
            .update(&client.id, |_| Ok::<_, ClientRegistryError>(client.clone()))
            .await
    })
    .await
}

/// A refresh-capable, untrusted client of `kind` with a fresh ID, calling back to
/// `{origin}/callback` and returning to `{origin}/logout` after logout.
pub(crate) fn registration(kind: ClientKind, origin: &str) -> ClientRegistration {
    ClientRegistration {
        id: format!("test-{}", UserId::new())
            .parse()
            .expect("client ID"),
        display_name: "Test app".parse().expect("display name"),
        kind,
        redirect_uris: RedirectUris::new([format!("{origin}/callback").parse().expect("callback")])
            .expect("one callback"),
        post_logout_uris: PostLogoutUris::new([format!("{origin}/logout")
            .parse()
            .expect("logout page")])
        .expect("one logout page"),
        allowed_scopes: AllowedScopes::new(
            [
                Scope::OpenId,
                Scope::Profile,
                Scope::Email,
                Scope::OfflineAccess,
            ]
            .map(ScopeName::from),
        )
        .expect("standard scopes"),
        allow_refresh: true,
        trusted: false,
        require_pushed_authorization_requests: false,
        backchannel_logout_uri: None,
    }
}

impl ClientSettings {
    /// What an owner chooses for a refresh-capable client calling back to
    /// `{origin}/callback`, with no post-logout page.
    pub(crate) fn test(origin: &str) -> Self {
        Self {
            display_name: "Notes".into(),
            redirect_uris: vec![format!("{origin}/callback")],
            post_logout_uris: Vec::new(),
            allowed_scopes: vec!["openid".into(), "offline_access".into()],
            allow_refresh: true,
            require_pushed_authorization_requests: false,
        }
    }
}

/// Adds `address` to `user_id` as verified, and primary if `is_primary`, and
/// returns its ID.
pub(crate) async fn verified_address(
    database: &Database,
    user_id: UserId,
    address: &str,
    is_primary: bool,
) -> EmailId {
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: EmailId::new(),
            user_id,
            normalized_email: address.into(),
            is_primary,
            verified_at: Utc::now(),
        })
        .await
        .expect("verified address")
        .id
}

/// Ends `session_id` of `user_id` in `tx`, as their browser's sign-out does.
pub(crate) async fn sign_out(
    tx: &mut DatabaseTransaction<'_>,
    user_id: UserId,
    session_id: SessionId,
) -> Result<Vec<SessionId>, DatabaseError> {
    let context = RequestContext::TEST.actor(Actor::User {
        user_id,
        session_id: Some(session_id),
    });
    tx.revoke_sessions(
        &context,
        user_id,
        SessionScope::One(session_id),
        &RevocationReason::Logout,
    )
    .await
}

/// Waits until `waiters` other transactions wait for a lock `holder` holds.
pub(crate) async fn until_blocked(holder: &mut DatabaseTransaction<'_>, waiters: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while holder.blocked_transactions().await.expect("lock waits") < waiters {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the operation waits for the holder's lock");
}

/// Issues the refresh grant `family` to `client` from `user_id`'s session
/// `session_id`, as a code exchange would, and returns its first refresh token's
/// ID and digest.
pub(crate) async fn refresh_grant(
    database: &Database,
    user_id: UserId,
    session_id: SessionId,
    client: &ClientId,
    family: TokenId,
) -> (TokenId, Vec<u8>) {
    let mut tx = database.begin().await.expect("transaction");
    let session = tx
        .sessions()
        .find_by_id(session_id)
        .await
        .expect("lookup")
        .expect("session");
    let authentication = SessionAuthentication::from(&session);
    let code = TokenId::new();
    tx.oidc()
        .insert_code(&InsertAuthorizationCode {
            id: code,
            secret_digest: code.as_uuid().as_bytes().repeat(2),
            digest_key: "test".into(),
            client_id: client.clone(),
            user_id,
            session_id,
            redirect_uri: "https://client.example/callback".into(),
            pkce_challenge: "challenge".into(),
            nonce: None,
            scopes: vec!["openid".into()],
            audience: client.to_string(),
            authentication: authentication.clone(),
            expires_at: Utc::now() + Duration::minutes(1),
        })
        .await
        .expect("code");
    let token = TokenId::new();
    let digest = token.as_uuid().as_bytes().repeat(2);
    tx.tokens()
        .insert_family(
            &InsertRefreshFamily {
                id: family,
                user_id,
                client_id: client.to_string(),
                session_id,
                authorization_code_id: code,
                audience: client.to_string(),
                scopes: vec!["openid".into()],
                authentication,
            },
            &InsertRefreshToken {
                id: token,
                family_id: family,
                secret_digest: digest.clone(),
                digest_key: "test".into(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await
        .expect("family");
    tx.commit().await.expect("commit");
    (token, digest)
}

/// HTTPS on a local port with a self-signed `localhost` certificate, so clients
/// reach local servers over HTTPS as they would in production.
pub(crate) struct TlsListener {
    /// Accepts TCP connections.
    tcp: tokio::net::TcpListener,
    /// Completes each TLS handshake.
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    /// Serves `router` on `tcp` in the background, with the request context
    /// `HttpSecurity` would attach, and returns the certificate to trust.
    pub(crate) fn serve(tcp: tokio::net::TcpListener, router: Router) -> reqwest::Certificate {
        use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )
        .expect("TLS configuration");
        let listener = Self {
            tcp,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        };
        let router = router.layer(axum::Extension(crate::security::RequestContext::TEST));
        tokio::spawn(async move { axum::serve(listener, router).await });
        reqwest::Certificate::from_der(certified.cert.der()).expect("trusted certificate")
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    /// Retries until a connection completes its handshake.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, address)) = self.tcp.accept().await else {
                continue;
            };
            if let Ok(stream) = self.acceptor.accept(stream).await {
                return (stream, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
