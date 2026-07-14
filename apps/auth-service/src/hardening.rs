//! Bounded public HTTP controls with sanitized, low-cardinality telemetry.

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

#[derive(Clone, Default)]
struct Limiter(Arc<Mutex<HashMap<(IpAddr, &'static str), Window>>>);
struct Window {
    started: Instant,
    count: u32,
}
pub(super) fn apply(router: Router) -> Router {
    let limiter = Limiter::default();
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(CatchPanicLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(10),
        ))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(middleware::from_fn_with_state(limiter, enforce))
}
async fn enforce(State(limiter): State<Limiter>, request: Request, next: Next) -> Response {
    let (class, limit) = classify(request.uri().path());
    let address = match request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip())
    {
        Some(address) => address,
        None if class == "public" => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "request source unavailable",
            )
                .into_response();
        }
    };
    let now = Instant::now();
    let mut windows = limiter.0.lock().await;
    if windows.len() > 10_000 {
        windows.retain(|_, window| now.duration_since(window.started) < Duration::from_mins(1));
    }
    let window = windows.entry((address, class)).or_insert(Window {
        started: now,
        count: 0,
    });
    if now.duration_since(window.started) >= Duration::from_mins(1) {
        *window = Window {
            started: now,
            count: 0,
        };
    }
    if window.count >= limit {
        tracing::warn!(
            endpoint_class = class,
            outcome = "rate_limited",
            "authentication request rejected"
        );
        return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
    }
    window.count += 1;
    drop(windows);
    let response = next.run(request).await;
    tracing::info!(
        endpoint_class = class,
        status = response.status().as_u16(),
        "authentication request completed"
    );
    response
}
fn classify(path: &str) -> (&'static str, u32) {
    if path.starts_with("/webauthn/") {
        ("webauthn", 30)
    } else if path.starts_with("/login/") {
        ("federation", 30)
    } else if path == "/oauth/token" || path == "/oauth/revoke" {
        ("token", 60)
    } else if path == "/oauth/authorize" {
        ("authorization", 60)
    } else if path.starts_with("/account/") {
        ("account", 60)
    } else {
        ("public", 300)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sensitive_routes_have_specific_bounds() {
        assert_eq!(classify("/oauth/token"), ("token", 60));
        assert_eq!(classify("/login/google/callback"), ("federation", 30));
        assert_eq!(classify("/webauthn/authenticate/start"), ("webauthn", 30));
    }
}
