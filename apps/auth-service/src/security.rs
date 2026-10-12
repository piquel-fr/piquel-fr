//! Shared browser-session, management authorization, and HTTP trust boundaries.

use axum::{
    Json,
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, UserId};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSession, StoredSession,
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: &'static str,
}
impl ApiError {
    pub(crate) fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "Sign in to continue.",
        }
    }
    pub(crate) fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message,
        }
    }
    pub(crate) fn internal(error: impl Into<anyhow::Error>) -> Self {
        tracing::error!(error = ?error.into(), "authentication operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "The request could not be completed. Please try again.",
        }
    }
}
impl From<DatabaseError> for ApiError {
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => {
                Self::bad_request("This request has expired or is no longer available.")
            }
            DatabaseError::Conflict => Self {
                status: StatusCode::CONFLICT,
                message: "This information is already in use.",
            },
            error => Self::internal(error),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({"error":self.message}))).into_response()
    }
}

/// Random 32-byte secrets travel base64url-encoded; only their digests reach the database.
pub(crate) struct BrowserSecret(Vec<u8>);
impl BrowserSecret {
    pub(crate) fn new() -> Self {
        let mut value = vec![0; 32];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .filter(|v| v.len() == 32)
            .map(Self)
    }
    pub(crate) fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }
    pub(crate) fn digest(&self) -> Vec<u8> {
        Sha256::digest(&self.0).to_vec()
    }
}

/// Host-only cookies that bind server-side state to a browser through a `BrowserSecret`.
#[derive(Clone, Copy)]
pub(crate) enum BrowserCookie {
    /// The central sign-in session.
    Session,
    /// An in-progress `WebAuthn` ceremony.
    Ceremony,
    /// A social login redirect awaiting its provider callback.
    Federation,
    /// A verified social identity awaiting signup or linking.
    FederationPending,
}
impl BrowserCookie {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Session => "__Host-piquel_session",
            Self::Ceremony => "__Host-piquel_ceremony",
            Self::Federation => "__Host-piquel_federation",
            Self::FederationPending => "__Host-piquel_federation_pending",
        }
    }
    /// Lifetime in seconds. Flow cookies outlive their server-side state slightly.
    const fn max_age(self) -> u32 {
        match self {
            Self::Session => 30 * 24 * 60 * 60,
            Self::Ceremony | Self::Federation | Self::FederationPending => 600,
        }
    }
    /// Reads this cookie's secret. A malformed or duplicated cookie counts as absent,
    /// so an injected value can never shadow the browser's own.
    pub(crate) fn read(self, headers: &HeaderMap) -> Option<BrowserSecret> {
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|part| part.trim().strip_prefix(self.name())?.strip_prefix('='));
        let value = values.next()?;
        values
            .next()
            .is_none()
            .then(|| BrowserSecret::parse(value))?
    }
    /// `Set-Cookie` value storing `secret` in this cookie.
    pub(crate) fn set(self, secret: &BrowserSecret) -> String {
        self.header(&secret.encoded(), self.max_age())
    }
    /// `Set-Cookie` value deleting this cookie.
    pub(crate) fn clear(self) -> String {
        self.header("", 0)
    }
    fn header(self, value: &str, max_age: u32) -> String {
        format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            self.name()
        )
    }
}

pub(crate) async fn optional_session(
    database: &Database,
    headers: &HeaderMap,
) -> Result<Option<StoredSession>, ApiError> {
    let Some(secret) = BrowserCookie::Session.read(headers) else {
        return Ok(None);
    };
    Ok(database
        .sessions()
        .find_active_by_browser_secret(&secret.digest())
        .await?)
}
pub(crate) async fn session(
    database: &Database,
    headers: &HeaderMap,
) -> Result<StoredSession, ApiError> {
    optional_session(database, headers)
        .await?
        .ok_or_else(ApiError::unauthorized)
}
pub(crate) async fn management(
    database: &Database,
    headers: &HeaderMap,
) -> Result<StoredSession, ApiError> {
    let session = session(database, headers).await?;
    if !database.sessions().management_active(session.id).await? {
        return Err(ApiError::forbidden(
            "Confirm with a passkey to unlock settings for two minutes.",
        ));
    }
    Ok(session)
}
pub(crate) async fn create_session(
    tx: &mut DatabaseTransaction<'_>,
    user_id: UserId,
    method: AuthenticationMethod,
) -> Result<String, ApiError> {
    let now = Utc::now();
    let id = SessionId::new();
    tx.sessions()
        .insert(&InsertSession {
            id,
            user_id,
            authentication_methods: vec![method],
            authenticated_at: now,
            expires_at: now + Duration::days(30),
            user_agent_family: None,
        })
        .await?;
    let secret = BrowserSecret::new();
    tx.sessions()
        .insert_browser_secret(id, &secret.digest())
        .await?;
    Ok(BrowserCookie::Session.set(&secret))
}

#[derive(Clone)]
pub(crate) struct HttpSecurity {
    pub database: Database,
    pub trusted_proxy_ips: Arc<Vec<IpAddr>>,
    pub request_timeout: StdDuration,
    pub auth_origin: String,
    pub settings_origin: String,
    pub client_origins: Arc<Vec<String>>,
}
impl HttpSecurity {
    /// A trusted edge must overwrite X-Real-IP with one validated client address.
    fn client_ip(&self, request: &Request) -> Result<IpAddr, ApiError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or_else(|| ApiError::internal(anyhow::anyhow!("HTTP peer address missing")))?
            .0
            .ip();
        if !self.trusted_proxy_ips.contains(&peer) {
            return Ok(peer);
        }
        let mut forwarded = request.headers().get_all("x-real-ip").iter();
        let ip = forwarded
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        if forwarded.next().is_some() {
            return Err(ApiError::bad_request(
                "Trusted proxy must supply one X-Real-IP address.",
            ));
        }
        ip.ok_or_else(|| ApiError::bad_request("Trusted proxy must supply one X-Real-IP address."))
    }

    fn rate_bucket(&self, request: &Request) -> Result<Option<Vec<u8>>, ApiError> {
        let Some(route) = request.extensions().get::<MatchedPath>() else {
            return Ok(None);
        };
        let path = route.as_str();
        let mutation = !matches!(*request.method(), Method::GET | Method::HEAD);
        let category = if matches!(
            path,
            "/oauth/token" | "/oauth/revoke" | "/oidc/token" | "/oidc/revoke"
        ) {
            "token"
        } else if mutation && (path.starts_with("/account/") || path == "/session/logout") {
            "account"
        } else if mutation || path.starts_with("/login/") || path == "/oauth/authorize" {
            "login"
        } else {
            return Ok(None);
        };
        Ok(Some(
            Sha256::digest(format!("{category}:{}", self.client_ip(request)?).as_bytes()).to_vec(),
        ))
    }

    fn allowed_origin(&self, path: &str, origin: &str) -> bool {
        origin == self.auth_origin
            || (origin == self.settings_origin
                && (path.starts_with("/account/")
                    || path.starts_with("/session")
                    || path == "/config"
                    || path.starts_with("/federation/")
                    || path.starts_with("/login/")))
            || (matches!(
                path,
                "/oauth/token"
                    | "/oauth/userinfo"
                    | "/oauth/revoke"
                    | "/oidc/token"
                    | "/oidc/userinfo"
                    | "/oidc/revoke"
                    | "/.well-known/openid-configuration"
                    | "/.well-known/jwks.json"
            ) && self.client_origins.iter().any(|v| v == origin))
    }

    pub(crate) async fn protect(
        State(policy): State<Self>,
        request: Request,
        next: Next,
    ) -> Response {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let path = request.uri().path();
        let allowed = origin
            .as_deref()
            .is_some_and(|v| policy.allowed_origin(path, v));
        let operation = async {
            let path = request.uri().path();
            if request.method() == Method::OPTIONS {
                if allowed {
                    StatusCode::NO_CONTENT.into_response()
                } else {
                    ApiError::forbidden("Origin is not allowed.").into_response()
                }
            } else {
                // OAuth endpoints enforce their protocol credentials and state;
                // authorization also accepts cross-site browser form navigation.
                let logout = path == "/oidc/logout";
                let protocol = logout
                    || matches!(
                        path,
                        "/oauth/token"
                            | "/oauth/revoke"
                            | "/oidc/token"
                            | "/oidc/revoke"
                            | "/oauth/authorize"
                            | "/oidc/authorize"
                            | "/oauth/userinfo"
                            | "/oidc/userinfo"
                    );
                let mutation = !matches!(*request.method(), Method::GET | Method::HEAD);
                if (origin.is_some() && !allowed && !protocol)
                    || (mutation
                        && !protocol
                        && (!allowed || request.headers().get("x-piquel-csrf").is_none()))
                {
                    ApiError::forbidden("This request must originate from an approved Piquel page.")
                        .into_response()
                } else {
                    let rate = match policy.rate_bucket(&request) {
                        Ok(Some(bucket)) => policy
                            .database
                            .security()
                            .allow_request(&bucket, 120)
                            .await
                            .map_err(ApiError::from),
                        Ok(None) => Ok(true),
                        Err(error) => Err(error),
                    };
                    match rate {
                    Ok(true) => next.run(request).await,
                    Ok(false) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, "60")],
                        Json(
                            serde_json::json!({"error":"Too many requests. Please wait a minute."}),
                        ),
                    )
                        .into_response(),
                    Err(error) => error.into_response(),
                }
                }
            }
        };
        let mut response = match tokio::time::timeout(policy.request_timeout, operation).await {
            Ok(response) => response,
            Err(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error":"Request timed out."})),
            )
                .into_response(),
        };
        Self::decorate(&mut response, origin, allowed);
        response
    }
    fn decorate(response: &mut Response, origin: Option<String>, allowed: bool) {
        let headers = response.headers_mut();
        if !headers.contains_key(header::CACHE_CONTROL) {
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
        if allowed {
            if let Some(origin) = origin.and_then(|v| HeaderValue::from_str(&v).ok()) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            }
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type, x-piquel-csrf, authorization"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, PATCH, DELETE, OPTIONS"),
            );
            headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
