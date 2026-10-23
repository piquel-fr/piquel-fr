//! Two instances of the whole service on one database, as piqueld runs replicas,
//! and the fixtures shared by the applications' tests.

use crate::{
    AuthConfig, ClientRegistry, ClientRegistryError, Operator,
    config::{EmailConfig, FederationConfig, FrontendOrigins, OidcConfig, PasskeyConfig},
    passkey::DecoyKey,
    security::{BrowserCookie, RequestContext, Session},
};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, ClientId, Handle, SessionId, TokenId, UserId,
    clients::{
        AllowedScopes, ClientField, ClientKind, ClientOwner, ClientRegistration, PostLogoutUris,
        RedirectUris, ScopeName,
    },
    config::{Origin, PublicUrl},
    events::{Actor, RevocationReason},
    protocol::oauth::Scope,
};
use piquel_crypto::{ClientSecret, Rs256Key, Secret};
use piquel_repository::{
    Database, DatabaseConfig, DatabaseError, DatabaseTransaction, InsertAuthorizationCode,
    InsertRefreshFamily, InsertRefreshToken, InsertUser, SessionAuthentication, SessionScope,
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

/// Two routers built by [`AuthConfig::router`] from one configuration. Each has its
/// own database pool and in-process state, so a test passes only if everything it
/// relies on is shared through PostgreSQL or the configuration.
pub(crate) struct Replicas {
    /// The first replica.
    pub a: Router,
    /// The second replica.
    pub b: Router,
}

impl Replicas {
    /// Builds both replicas. Every request comes from one client address, unique to
    /// this fixture, so the replicas share its rate-limit budget and no other test's.
    pub(crate) async fn new() -> Self {
        let origin: Origin = AUTH_ORIGIN.parse().expect("auth origin");
        let settings_url: PublicUrl = "https://piquel.fr/settings".parse().expect("settings URL");
        let config = AuthConfig {
            public_listener: SocketAddr::from(([127, 0, 0, 1], 0)),
            admin_listener: None,
            passkey: PasskeyConfig {
                origin: origin.clone(),
                invite_required: false,
                decoy_key: DecoyKey::new(Secret::generate().expect("decoy key")),
            },
            email: EmailConfig::test(&settings_url, true),
            federation: FederationConfig {
                origin: origin.clone(),
                frontends: FrontendOrigins::new([&settings_url]),
                settings_url,
                providers: BTreeMap::new(),
            },
            oidc: OidcConfig {
                origin,
                keys: Arc::new(Rs256Key::generate("replicas").expect("signing key")),
                refresh_key: Arc::new(Secret::generate().expect("refresh key")),
            },
            trusted_proxies: vec![],
        };
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128())),
            4321,
        );
        let replica = async || {
            config
                .router(Self::database().await)
                .expect("replica")
                .layer(Extension(ConnectInfo(peer)))
        };
        Self {
            a: replica().await,
            b: replica().await,
        }
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

/// Largest response body [`Browser::call`] reads.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

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
        let secret = Session::create(&mut tx, RequestContext::TEST, user_id, method)
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
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .extension(RequestContext::TEST)
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &self.cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

/// The operator client changes made by tests are attributed to, as the `client`
/// command's are.
pub(crate) fn operator() -> Operator {
    Operator::Cli {
        os_user: "test".into(),
        host: "test".into(),
    }
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
