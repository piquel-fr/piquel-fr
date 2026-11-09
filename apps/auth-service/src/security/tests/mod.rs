//! Focused persistence and security contract tests.

use super::*;
use super::{
    endpoint::{Endpoint, RateCategory},
    http::{CorsGrant, FETCH_SITE_HEADER, FORWARDED_FOR_HEADER, Listener},
};
use crate::routes::{oidc, page, service};
use crate::tests::REQUESTS_PER_MINUTE;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, Method, Request as HttpRequest},
    middleware,
    routing::any,
};
use chrono::{Duration, Utc};
use ipnet::IpNet;
use sourceorigin_common::{
    AuthenticationMethod, SessionId, UserId,
    clients::{ClientKind, ClientOwner},
    events::{Actor, Browser, Platform, RevocationReason, UserAgentFamily},
};
use sourceorigin_crypto::Digest;
use sourceorigin_repository::{Database, SessionScope, StoredSession};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tower::ServiceExt;

mod caching;
mod forwarding;
mod origins;
mod rate_limits;
mod sessions;

impl RequestContext {
    /// The context of a request from a documentation address, for handler tests
    /// that bypass [`HttpSecurity::protect`].
    pub(crate) const TEST: Self = Self {
        client_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        user_agent_family: UserAgentFamily {
            browser: Browser::Firefox,
            platform: Platform::Linux,
        },
    };

    /// The context of a request from `client_ip`, for handler tests that keep
    /// their per-IP limits apart from other tests'.
    pub(crate) const fn from_ip(client_ip: IpAddr) -> Self {
        Self {
            client_ip,
            ..Self::TEST
        }
    }
}

/// Asserts that `response` asks the frontend to confirm the session with a passkey
/// at most [`CONFIRMATION_MAX_AGE`] seconds old, in the stable JSON shape.
pub(crate) async fn assert_step_up_required(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body"),
    )
    .expect("JSON");
    assert_eq!(
        body,
        serde_json::json!({
            "error": "Confirm with your passkey to continue.",
            "code": "step_up_required",
            "max_age": CONFIRMATION_MAX_AGE,
        })
    );
}

/// An isolated request router and database for HTTP trust-boundary scenarios.
struct SecurityFixture {
    /// Dummy routes protected by the production middleware.
    router: Router,
    /// Unique peer address separates concurrent test budgets.
    peer: SocketAddr,
    /// Editable policy for proxy and deadline scenarios.
    policy: HttpSecurity,
}
impl SecurityFixture {
    /// Builds a test policy with exact browser origins and unique client buckets.
    /// A public client calls back to `https://external.example`.
    async fn new() -> Self {
        let database = crate::tests::Replicas::database().await;
        database
            .oidc()
            .create_client(
                &crate::tests::registration(ClientKind::Public, "https://external.example"),
                ClientOwner::Operator,
            )
            .await
            .expect("public client");
        let policy = HttpSecurity {
            trusted_proxies: Arc::new(vec![]),
            request_timeout: std::time::Duration::from_secs(30),
            requests_per_minute: REQUESTS_PER_MINUTE,
            database,
            origin: site(),
            listener: Listener::Public,
        };
        let mut router = Router::new();
        for path in [
            "/account/passkeys",
            "/webauthn/authenticate/start",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/audit/checkpoints",
            "/audit/checkpoints/latest",
            "/oauth/token",
            "/oauth/authorize",
            "/oauth/revoke",
            "/oidc/userinfo",
            "/oidc/logout",
        ] {
            router = router.route(path, any(|| async { StatusCode::ACCEPTED }));
        }
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128())),
            4321,
        );
        Self {
            router: router.layer(middleware::from_fn_with_state(
                policy.clone(),
                HttpSecurity::protect,
            )),
            peer,
            policy,
        }
    }
    /// Sends a request with selected browser proof and explicit peer metadata.
    async fn request(
        &self,
        method: Method,
        path: &str,
        origin: Option<&str>,
        csrf: bool,
    ) -> Response {
        let mut request = HttpRequest::builder().method(method.clone()).uri(path);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if csrf {
            request = request.header("x-sourceorigin-csrf", "1");
        }
        if method == Method::OPTIONS {
            request = request
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "content-type, x-sourceorigin-csrf",
                );
        }
        let mut request = request.body(Body::empty()).expect("request");
        request.extensions_mut().insert(ConnectInfo(self.peer));
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("response")
    }
    /// Checks CORS reflects exactly the approved origin, without the browser's
    /// cookies.
    fn exact_cors(response: &Response, origin: &str) {
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            origin
        );
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
        assert_eq!(response.headers()[header::VARY], "Origin");
        assert_ne!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }
    /// Checks rejected origins receive browser isolation headers and no CORS grant.
    fn denied(response: &Response) {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, no-transform"
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
    }
}

/// The origin of auth's own pages in the policy tests.
fn site() -> url::Origin {
    url::Url::parse("https://auth.sourceorigin.dev")
        .expect("URL")
        .origin()
}
