use crate::{
    StartupError,
    config::{AUTH_MOUNT, AdminConfig},
    pages,
};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, header::InvalidHeaderValue},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use piquel_admin_api::AdminClient;
use piquel_auth::{
    Issuer,
    axum::{LoginRoutes, MemoryBackend},
};
use piquel_common::{ErrorChain, protocol::oauth::Scope};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use topcoat::router::tower::TowerService;
use tower::ServiceExt;

/// How long one discovery request may take.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait before discovering auth again after a failure.
const DISCOVERY_RETRY: Duration = Duration::from_secs(5);
/// Scopes besides `openid`. `offline_access` refreshes the five-minute access
/// tokens for as long as the dashboard session lasts.
const SCOPES: [Scope; 2] = [Scope::Profile, Scope::OfflineAccess];

/// The dashboard's HTTP service: a health check, and everything else once auth's
/// issuer is discovered.
///
/// Discovery runs in the background and retries until auth answers, so the
/// dashboard starts, and passes its health check, while auth or its route is still
/// coming up. Until then, pages answer `503`.
pub struct Dashboard {
    /// The pages with sign-in, set once discovery succeeds.
    ready: Arc<OnceLock<Router>>,
    /// The security headers of every response.
    headers: Arc<HeaderMap>,
}

impl Dashboard {
    /// Starts discovering auth in the background.
    ///
    /// # Errors
    /// If the security headers or an HTTP client cannot be built.
    pub fn new(config: AdminConfig) -> Result<Self, StartupError> {
        let headers = Arc::new(Self::security_headers(&config)?);
        let api = AdminClient::new(config.api.clone())?;
        let http = reqwest::Client::builder()
            .timeout(DISCOVERY_TIMEOUT)
            // No auth endpoint redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(StartupError::AuthClient)?;
        let ready = Arc::new(OnceLock::new());
        tokio::spawn(Self::discover(config, http, api, Arc::clone(&ready)));
        Ok(Self { ready, headers })
    }

    /// The service to serve.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .fallback(Self::forward)
            .with_state(Arc::clone(&self.ready))
            .layer(middleware::map_response_with_state(
                Arc::clone(&self.headers),
                Self::secure,
            ))
    }

    /// Headers that keep account data on the administrator's screen only: no page
    /// is cached, framed (against clickjacking a change's button) or sends a
    /// referrer. Pages load only the dashboard's stylesheet, and forms post only
    /// to the dashboard, whose sign-out continues to auth.
    fn security_headers(config: &AdminConfig) -> Result<HeaderMap, InvalidHeaderValue> {
        let policy = format!(
            "default-src 'none'; style-src 'self'; form-action 'self' {}; \
             frame-ancestors 'none'; base-uri 'none'",
            config.issuer.serialized()
        );
        Ok(HeaderMap::from_iter([
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::try_from(policy)?,
            ),
            (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000"),
            ),
        ]))
    }

    /// Adds the security headers to a response.
    fn secure(
        State(headers): State<Arc<HeaderMap>>,
        mut response: Response,
    ) -> std::future::Ready<Response> {
        response.headers_mut().extend(headers.as_ref().clone());
        std::future::ready(response)
    }

    /// Resolves on Ctrl+C or `SIGTERM`, which start graceful shutdown.
    pub async fn shutdown_signal() {
        let interrupt = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %ErrorChain(&error), "could not listen for Ctrl+C");
                std::future::pending::<()>().await;
            }
        };
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => {
                    tracing::error!(error = %ErrorChain(&error), "could not listen for SIGTERM");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = interrupt => {}
            () = terminate => {}
        }
    }

    /// Sends a request to the pages, or answers `503` before discovery.
    async fn forward(State(ready): State<Arc<OnceLock<Router>>>, request: Request) -> Response {
        match ready.get() {
            Some(pages) => match pages.clone().oneshot(request).await {
                Ok(response) => response,
                Err(infallible) => match infallible {},
            },
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                "The dashboard is still connecting to auth; try again in a few seconds.",
            )
                .into_response(),
        }
    }

    /// Discovers auth's issuer until it answers, then builds the pages.
    async fn discover(
        config: AdminConfig,
        http: reqwest::Client,
        api: AdminClient,
        ready: Arc<OnceLock<Router>>,
    ) {
        let issuer = loop {
            match Issuer::builder()
                .http_client(http.clone())
                .discover(&config.issuer.serialized())
                .await
            {
                Ok(issuer) => break issuer,
                Err(error) => {
                    tracing::warn!(error = %ErrorChain(&error), "auth discovery failed; retrying");
                    tokio::time::sleep(DISCOVERY_RETRY).await;
                }
            }
        };
        let scopes = SCOPES.map(|scope| scope.as_str().to_owned());
        let login = LoginRoutes::new(issuer.client(config.client), MemoryBackend::default())
            .scopes(scopes.into_iter().collect())
            .after_logout(config.origin.url("/"));
        let pages = Router::new()
            .nest(AUTH_MOUNT, login.router())
            .fallback_service(TowerService::new(pages::router(api)))
            .layer(login.layer());
        let _ = ready.set(pages);
        tracing::info!(issuer = %issuer.issuer(), "connected to auth");
    }
}
