//! Bounded public HTTP controls with an explicit trusted-proxy boundary.

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

const MAX_WINDOWS: usize = 10_000;
const EVICTIONS_PER_REQUEST: usize = 64;

#[derive(Clone)]
pub(crate) enum IngressPolicy {
    Direct,
    TrustedProxies(Arc<[IpNet]>),
}

#[derive(Clone)]
struct Limiter {
    ingress: IngressPolicy,
    state: Arc<Mutex<LimiterState>>,
}
#[derive(Default)]
struct LimiterState {
    windows: HashMap<(IpAddr, &'static str), Window>,
    order: VecDeque<(Instant, (IpAddr, &'static str))>,
}
struct Window {
    started: Instant,
    count: u32,
}

pub(super) fn apply(router: Router, ingress: IngressPolicy) -> Router {
    let limiter = Limiter {
        ingress,
        state: Arc::default(),
    };
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
    let Some(address) = client_address(&request, &limiter.ingress) else {
        tracing::warn!(
            endpoint_class = class,
            outcome = "untrusted_proxy",
            "request rejected"
        );
        return (StatusCode::BAD_REQUEST, "invalid forwarding boundary").into_response();
    };
    let now = Instant::now();
    let key = (address, class);
    let mut state = limiter.state.lock().await;
    evict_expired(&mut state, now);
    if !state.windows.contains_key(&key) && state.windows.len() >= MAX_WINDOWS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "rate limiter capacity reached",
        )
            .into_response();
    }
    let reset = state
        .windows
        .get(&key)
        .is_none_or(|window| now.duration_since(window.started) >= Duration::from_mins(1));
    if reset {
        state.windows.insert(
            key,
            Window {
                started: now,
                count: 0,
            },
        );
        state.order.push_back((now, key));
    }
    let window = state.windows.get_mut(&key).expect("window was inserted");
    if window.count >= limit {
        tracing::warn!(
            endpoint_class = class,
            outcome = "rate_limited",
            "authentication request rejected"
        );
        return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
    }
    window.count += 1;
    drop(state);
    let response = next.run(request).await;
    tracing::info!(
        endpoint_class = class,
        status = response.status().as_u16(),
        "authentication request completed"
    );
    response
}

fn evict_expired(state: &mut LimiterState, now: Instant) {
    for _ in 0..EVICTIONS_PER_REQUEST {
        let Some((started, key)) = state.order.front().copied() else {
            break;
        };
        if now.duration_since(started) < Duration::from_mins(1) {
            break;
        }
        state.order.pop_front();
        if state
            .windows
            .get(&key)
            .is_some_and(|window| window.started == started)
        {
            state.windows.remove(&key);
        }
    }
}

fn client_address(request: &Request, ingress: &IngressPolicy) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip();
    match ingress {
        IngressPolicy::Direct => Some(peer),
        IngressPolicy::TrustedProxies(proxies) => {
            if !proxies.iter().any(|network| network.contains(&peer)) {
                return None;
            }
            let forwarded = request.headers().get("x-forwarded-for")?.to_str().ok()?;
            if forwarded.len() > 512 {
                return None;
            }
            forwarded.split(',').next()?.trim().parse().ok()
        }
    }
}

fn classify(path: &str) -> (&'static str, u32) {
    if path.starts_with("/webauthn/") {
        ("webauthn", 30)
    } else if path.starts_with("/login/") {
        ("federation", 30)
    } else if path == "/oauth/token" || path == "/oauth/revoke" {
        ("token", 60)
    } else if path.starts_with("/oauth/authorize") {
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

    #[test]
    fn eviction_work_is_bounded() {
        let now = Instant::now();
        let mut state = LimiterState::default();
        for offset in 0..100 {
            let key = (IpAddr::from([10, 0, 0, offset]), "public");
            let started = now
                .checked_sub(Duration::from_mins(2))
                .expect("test instant supports two-minute subtraction");
            state.windows.insert(key, Window { started, count: 1 });
            state.order.push_back((started, key));
        }
        evict_expired(&mut state, now);
        assert_eq!(state.windows.len(), 100 - EVICTIONS_PER_REQUEST);
    }

    #[test]
    fn forwarded_address_is_accepted_only_from_traefik_network() {
        let mut request = Request::builder()
            .header("x-forwarded-for", "203.0.113.7, 172.18.0.2")
            .body(axum::body::Body::empty())
            .expect("request");
        request.extensions_mut().insert(ConnectInfo(
            "172.18.0.2:443".parse::<SocketAddr>().expect("peer"),
        ));
        let trusted = IngressPolicy::TrustedProxies(
            vec!["172.18.0.0/16".parse::<IpNet>().expect("network")].into(),
        );
        assert_eq!(
            client_address(&request, &trusted),
            Some("203.0.113.7".parse().expect("client IP"))
        );
        let untrusted = IngressPolicy::TrustedProxies(
            vec!["10.0.0.0/8".parse::<IpNet>().expect("network")].into(),
        );
        assert_eq!(client_address(&request, &untrusted), None);
    }
}
