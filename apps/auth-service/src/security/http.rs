//! Shared HTTP trust boundaries: origin, proxy, timeout, request-limit and
//! in-flight-limit policy, and the cache, isolation and CORS headers of every response.

use super::endpoint::Endpoint;
use super::{ApiError, CSRF_HEADER, RequestContext};
use axum::{
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{self, InvalidHeaderValue},
        uri::Authority,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use piquel_common::{config::Origin, protocol::same_origin::BrowserRequest};
use piquel_crypto::Digest;
use piquel_repository::{Database, DatabaseError};
use piquel_telemetry::{Counter, HttpTelemetry, Label};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use thiserror::Error;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Fetch metadata header naming how a request's initiator relates to its target.
pub(crate) const FETCH_SITE_HEADER: &str = "sec-fetch-site";
/// Trusted ingress must overwrite this header with exactly one client address.
pub(super) const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
/// Requests refused because their client's budget was exhausted, by category, or
/// because too many were in flight, as `overloaded`.
static THROTTLED: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.throttled",
    "{request}",
    "Requests refused by rate limits, by rate category, or as overloaded.",
);
/// The fixed window request budgets count in.
const RATE_WINDOW: StdDuration = StdDuration::from_mins(1);
/// Deadline includes origin checks, rate-limit persistence and the handler.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// Requests each listener runs at once. More are refused at once instead of
/// queueing for the database pool's 10 connections until their deadline.
pub(super) const MAX_IN_FLIGHT: usize = 64;
/// When a request refused for [`MAX_IN_FLIGHT`] may try again.
const OVERLOADED_RETRY: StdDuration = StdDuration::from_secs(1);

/// The CORS headers a response carries.
pub(super) enum CorsGrant {
    /// Public, credential-free documents that any origin may read.
    Public,
    /// An approved origin, which calls without the browser's cookies: a public
    /// client's, on the back channel and userinfo. Auth's own pages need no grant,
    /// being same-origin.
    Client(HeaderValue),
    /// An approved related origin, whose page signs users in with passkeys,
    /// without cookies but with Piquel's CSRF header.
    Related(HeaderValue),
}

/// Who may store a response, and for how long. Handlers choose a class with [`Cached`];
/// [`HttpSecurity::decorate`] enforces it on every response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheClass {
    /// Never stored: pages, APIs, OAuth, errors and every response without a class.
    NoStore,
    /// Content that never changes at its URL: the build assets, named by their
    /// content, and profile pictures, named by their upload. Any cache may keep it
    /// for a year.
    Immutable,
    /// Public, credential-free data, the same for every caller and readable from any
    /// origin. Its route must accept any `Origin` and never read the session.
    Public { max_age: StdDuration },
}

impl CacheClass {
    /// The class a response keeps: its handler's, unless it sets a cookie or is
    /// anything but a success.
    fn enforced(response: &Response) -> Self {
        match response.extensions().get::<Self>() {
            Some(&class)
                if response.status() == StatusCode::OK
                    && !response.headers().contains_key(header::SET_COOKIE) =>
            {
                class
            }
            _ => Self::NoStore,
        }
    }

    /// The `Cache-Control` value of this class. Every value forbids transforming the
    /// body: Cloudflare's edge would otherwise rewrite pages, hiding email addresses
    /// behind a decoding script the Content-Security-Policy blocks.
    fn cache_control(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::NoStore => "no-store, no-transform",
            Self::Immutable => "public, max-age=31536000, immutable, no-transform",
            Self::Public { max_age } => {
                // Digits and fixed text always form a valid header value.
                return HeaderValue::try_from(format!(
                    "public, max-age={}, no-transform",
                    max_age.as_secs()
                ))
                .unwrap_or(HeaderValue::from_static("no-store, no-transform"));
            }
        })
    }
}

/// The only way to mark a response cacheable: wraps a handler's response with its class.
pub(crate) struct Cached<T>(pub CacheClass, pub T);

impl<T: IntoResponse> IntoResponse for Cached<T> {
    /// Attaches the class for [`HttpSecurity::decorate`] to enforce.
    fn into_response(self) -> Response {
        let mut response = self.1.into_response();
        response.extensions_mut().insert(self.0);
        response
    }
}

/// Failures in shared HTTP trust checks, preserving actionable internal sources.
#[derive(Debug, Error)]
pub(crate) enum HttpSecurityError {
    /// The listener did not attach its peer connection metadata.
    #[error("HTTP peer address missing")]
    MissingPeer,
    /// A handler that records events runs on a route without a rate budget, so the
    /// middleware attached no request context.
    #[error("request context missing")]
    MissingContext,
    /// A browser preflight came from an unapproved origin.
    #[error("preflight origin is not allowed")]
    ForbiddenPreflight,
    /// A browser request comes from an origin this endpoint does not serve.
    #[error("request origin is not allowed")]
    ForbiddenOrigin,
    /// A mutation carries no `Origin` header, so its page cannot be checked.
    #[error("mutation has no Origin header")]
    MissingOrigin,
    /// A form was posted to one of auth's pages from somewhere else.
    #[error("page form posted from another origin")]
    ForeignForm,
    /// The request names a host this listener does not serve.
    #[error("request host is not this listener's")]
    WrongHost,
    /// An approved browser mutation omitted its CSRF proof.
    #[error("browser mutation requires CSRF header")]
    MissingCsrf,
    /// The trusted proxy sent no forwarded address.
    #[error("trusted proxy sent no forwarded address")]
    MissingForwardedAddress,
    /// The trusted proxy sent several forwarded headers instead of overwriting them.
    #[error("trusted proxy sent several forwarded address headers")]
    MultipleForwardedHeaders,
    /// The forwarded header is not valid HTTP text.
    #[error("forwarded address is not HTTP text")]
    ForwardedHeader(#[from] axum::http::header::ToStrError),
    /// The forwarded header does not contain a single IP address.
    #[error("forwarded address is not a single IP address")]
    ForwardedAddress(#[from] std::net::AddrParseError),
    /// This client's category budget is exhausted.
    #[error("request budget exhausted")]
    RateLimited,
    /// The listener already runs [`MAX_IN_FLIGHT`] requests.
    #[error("too many requests in flight")]
    Overloaded,
    /// The complete request exceeded its deadline.
    #[error("HTTP request timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    /// Rate-limit persistence failed.
    #[error("HTTP security persistence failed")]
    Database(#[from] DatabaseError),
}

impl From<HttpSecurityError> for ApiError {
    /// Maps trust-boundary failures to stable public statuses and messages.
    fn from(error: HttpSecurityError) -> Self {
        match error {
            HttpSecurityError::ForbiddenPreflight | HttpSecurityError::ForbiddenOrigin => {
                Self::forbidden("This endpoint does not accept requests from this origin.")
            }
            HttpSecurityError::MissingOrigin => {
                Self::forbidden("This request must come from a Piquel page, with an Origin header.")
            }
            HttpSecurityError::ForeignForm => {
                Self::forbidden("Submit this form from its page on this site.")
            }
            HttpSecurityError::WrongHost => Self::new(
                StatusCode::MISDIRECTED_REQUEST,
                "This host is not served here.",
            ),
            HttpSecurityError::MissingCsrf => Self::forbidden(format!(
                "This request must come from a Piquel page, with the {CSRF_HEADER} header."
            )),
            HttpSecurityError::MissingForwardedAddress => {
                Self::bad_request("The proxy must send the client address in X-Forwarded-For.")
            }
            HttpSecurityError::MultipleForwardedHeaders => Self::bad_request(
                "The proxy must send exactly one X-Forwarded-For header, overwriting any other.",
            ),
            HttpSecurityError::ForwardedHeader(_) => {
                Self::bad_request("The proxy's X-Forwarded-For header is not valid text.")
            }
            HttpSecurityError::ForwardedAddress(_) => Self::bad_request(
                "The proxy's X-Forwarded-For header must hold exactly one IP address.",
            ),
            HttpSecurityError::RateLimited => {
                Self::too_many_requests("Too many requests. Please wait a minute.", RATE_WINDOW)
            }
            HttpSecurityError::Overloaded => Self {
                retry_after: Some(OVERLOADED_RETRY),
                ..Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The service is busy. Please try again in a moment.",
                )
            },
            HttpSecurityError::Timeout(_) => {
                Self::new(StatusCode::GATEWAY_TIMEOUT, "Request timed out.")
            }
            HttpSecurityError::Database(error) => error.into(),
            error @ (HttpSecurityError::MissingPeer | HttpSecurityError::MissingContext) => {
                Self::internal(error)
            }
        }
    }
}

/// Shared origin, proxy, timeout, request-limit and in-flight-limit policy, one
/// per listener.
#[derive(Clone)]
pub(crate) struct HttpSecurity {
    /// Stores the rate-limit counters.
    pub database: Database,
    /// Peers allowed to report the client IP in `X-Forwarded-For`.
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /// Deadline for the whole request, handler included.
    pub request_timeout: StdDuration,
    /// Request budget per category and client in each [`RATE_WINDOW`].
    pub requests_per_minute: i32,
    /// The listener's slots for requests in flight, [`MAX_IN_FLIGHT`] of them.
    /// Each listener has its own, so a flood of public requests never locks
    /// administrators out of the dashboard.
    pub in_flight: Arc<Semaphore>,
    /// Origin of the listener's own pages, allowed on every endpoint.
    pub origin: url::Origin,
    /// Which listener it guards.
    pub(super) listener: Listener,
}

/// The listener an [`HttpSecurity`] guards.
#[derive(Clone)]
pub(super) enum Listener {
    /// Auth's public listener: protocol endpoints, JSON APIs and pages, each
    /// classified by its route.
    Public,
    /// The admin listener, which serves only the dashboard's pages, and only to
    /// requests naming the dashboard's host, this `Host` header value: a request
    /// reaching it under another name, by a misrouted ingress or a rebound DNS
    /// name, is refused before anything runs.
    Admin(HeaderValue),
}

impl HttpSecurity {
    /// Derives the public listener's policy from validated startup configuration.
    pub(crate) fn new(config: &crate::AuthConfig, database: Database) -> Self {
        Self {
            database,
            trusted_proxies: Arc::new(config.trusted_proxies.clone()),
            request_timeout: REQUEST_TIMEOUT,
            requests_per_minute: config.requests_per_minute,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            origin: config.passkey.origin.as_url().origin(),
            listener: Listener::Public,
        }
    }

    /// Derives the admin listener's policy, for the dashboard at `dashboard`, from
    /// validated startup configuration.
    pub(crate) fn admin(
        config: &crate::AuthConfig,
        database: Database,
        dashboard: &Origin,
    ) -> Result<Self, InvalidHeaderValue> {
        // What browsers send: the host, and the port unless it is the scheme's own.
        let host = match dashboard.as_url().port() {
            Some(port) => format!("{}:{port}", dashboard.host()),
            None => dashboard.host().to_owned(),
        };
        Ok(Self {
            listener: Listener::Admin(HeaderValue::from_str(&host)?),
            origin: dashboard.as_url().origin(),
            ..Self::new(config, database)
        })
    }

    /// Refuses a request to the admin listener that names another host, by its
    /// `Host` header or, over HTTP/2, its authority.
    fn check_host(&self, request: &Request) -> Result<(), HttpSecurityError> {
        let Listener::Admin(expected) = &self.listener else {
            return Ok(());
        };
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| request.uri().authority().map(Authority::as_str));
        match host {
            Some(host) if host.eq_ignore_ascii_case(expected.to_str().unwrap_or_default()) => {
                Ok(())
            }
            _ => Err(HttpSecurityError::WrongHost),
        }
    }

    /// Takes one of the listener's slots for a request to `endpoint`, held until
    /// its response is ready, or refuses the request at once when none is free.
    /// Health probes take none: a busy replica is not a broken one, and piqueld
    /// must not restart it for being busy.
    fn admit(&self, endpoint: Endpoint) -> Result<Option<SemaphorePermit<'_>>, HttpSecurityError> {
        if matches!(endpoint, Endpoint::Health) {
            return Ok(None);
        }
        let Ok(permit) = self.in_flight.try_acquire() else {
            THROTTLED.add(1, &[("category", "overloaded")]);
            return Err(HttpSecurityError::Overloaded);
        };
        Ok(Some(permit))
    }

    /// A trusted edge must overwrite `X-Forwarded-For` with one validated client address.
    pub(super) fn client_ip(&self, request: &Request) -> Result<IpAddr, HttpSecurityError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or(HttpSecurityError::MissingPeer)?
            .0
            .ip();
        if !self
            .trusted_proxies
            .iter()
            .any(|proxy| proxy.contains(&peer))
        {
            return Ok(peer);
        }
        Self::forwarded_ip(request.headers())
    }

    /// Parses the one address an explicitly trusted ingress must supply.
    pub(super) fn forwarded_ip(headers: &HeaderMap) -> Result<IpAddr, HttpSecurityError> {
        let mut forwarded = headers.get_all(FORWARDED_FOR_HEADER).iter();
        let header = forwarded
            .next()
            .ok_or(HttpSecurityError::MissingForwardedAddress)?;
        if forwarded.next().is_some() {
            return Err(HttpSecurityError::MultipleForwardedHeaders);
        }
        Ok(header.to_str()?.parse()?)
    }

    /// Determines whether an exact browser origin may access this endpoint family:
    /// any origin reads discovery and the audit checkpoints, and auth's own pages
    /// reach every endpoint. The
    /// back-channel and `UserInfo` endpoints also serve the redirect origins of
    /// enabled public clients, and related sign-in the approved origins of trusted
    /// clients. Those are looked up per request, so registration changes apply at
    /// once; same-origin requests skip the query.
    async fn allowed_origin(
        &self,
        endpoint: Endpoint,
        origin: &str,
    ) -> Result<bool, HttpSecurityError> {
        if matches!(
            endpoint,
            Endpoint::Discovery | Endpoint::Checkpoints | Endpoint::Picture
        ) || origin == self.origin.ascii_serialization()
        {
            return Ok(true);
        }
        Ok(match endpoint {
            Endpoint::OAuthBackChannel | Endpoint::UserInfo => {
                self.database.oidc().public_client_origin(origin).await?
            }
            Endpoint::RelatedLogin => self
                .database
                .oidc()
                .related_origin_client(origin)
                .await?
                .is_some(),
            Endpoint::Discovery
            | Endpoint::Checkpoints
            | Endpoint::Picture
            | Endpoint::Health
            | Endpoint::Authorize
            | Endpoint::Logout
            | Endpoint::Account
            | Endpoint::Page
            | Endpoint::Dashboard
            | Endpoint::Other => false,
        })
    }

    /// Middleware: sheds the request if the listener is full, runs the trust checks
    /// and the handler under one deadline, then adds the cache, isolation and CORS
    /// headers to every response, errors included.
    /// Discovery's errors and preflights get the public grant from their endpoint.
    pub(crate) async fn protect(
        State(policy): State<Self>,
        request: Request,
        next: Next,
    ) -> Response {
        // Reuse the original header for CORS so decoration cannot fail during re-parsing.
        let origin = request.headers().get(header::ORIGIN).cloned();
        let endpoint = match policy.listener {
            Listener::Public => Endpoint::of(&request),
            Listener::Admin(_) => Endpoint::Dashboard,
        };
        let slot = policy.admit(endpoint);
        // Set by the origin check, which runs under the deadline; an error response
        // still carries CORS headers once the origin is known to be allowed. A
        // refusal for overload skips the check, which may query the database, and
        // any origin may read it: it says only when to try again.
        let mut allowed = slot.is_err();
        let mut response = tokio::time::timeout(policy.request_timeout, async {
            let _slot = slot?;
            policy.check_host(&request)?;
            if let Some(value) = origin.as_ref().and_then(|value| value.to_str().ok()) {
                allowed = policy.allowed_origin(endpoint, value).await?;
            }
            policy.dispatch(request, next, endpoint, allowed).await
        })
        .await
        .map_err(HttpSecurityError::from)
        .flatten()
        .unwrap_or_else(|error| ApiError::from(error).into_response());
        let grant = match endpoint {
            Endpoint::Discovery | Endpoint::Checkpoints | Endpoint::Picture => {
                Some(CorsGrant::Public)
            }
            Endpoint::RelatedLogin => origin.filter(|_| allowed).map(CorsGrant::Related),
            _ => origin.filter(|_| allowed).map(CorsGrant::Client),
        };
        Self::decorate(&mut response, grant);
        response
    }

    /// Answers preflights, then checks browser proof and the request budget before the
    /// route, and attaches the [`RequestContext`] of rate-limited routes.
    async fn dispatch(
        &self,
        mut request: Request,
        next: Next,
        endpoint: Endpoint,
        allowed: bool,
    ) -> Result<Response, HttpSecurityError> {
        if request.method() == Method::OPTIONS {
            return if allowed {
                Ok(StatusCode::NO_CONTENT.into_response())
            } else {
                Err(HttpSecurityError::ForbiddenPreflight)
            };
        }
        let mutation = !matches!(*request.method(), Method::GET | Method::HEAD);
        Self::check_browser(endpoint, request.headers(), allowed, mutation, &self.origin)?;
        // Unknown paths have no `MatchedPath`: they never consume a budget or need peer metadata.
        if request.extensions().get::<MatchedPath>().is_some()
            && let Some(category) = endpoint.rate_category()
        {
            let client_ip = self.client_ip(&request)?;
            let bucket = Digest::sha256(format!("{category}:{client_ip}").as_bytes());
            if !self
                .database
                .security()
                .allow_request(bucket.as_bytes(), self.requests_per_minute, RATE_WINDOW)
                .await?
            {
                THROTTLED.add(1, &[("category", category.as_str())]);
                return Err(HttpSecurityError::RateLimited);
            }
            let context = RequestContext::new(client_ip, request.headers());
            request.extensions_mut().insert(context);
        }
        Ok(next.run(request).await)
    }

    /// Rejects unapproved browser origins and mutations without CSRF proof. Protocol
    /// endpoints are exempt: their handlers check credentials and navigation themselves.
    /// Pages take any navigation, but a form only from `site`'s own pages
    /// ([`BrowserRequest::is_same_origin`]): a plain form cannot send the CSRF header,
    /// and sends `Origin: null` under `Referrer-Policy: no-referrer`.
    pub(super) fn check_browser(
        endpoint: Endpoint,
        headers: &HeaderMap,
        allowed: bool,
        mutation: bool,
        site: &url::Origin,
    ) -> Result<(), HttpSecurityError> {
        if endpoint.is_protocol() {
            return Ok(());
        }
        if matches!(endpoint, Endpoint::Page | Endpoint::Dashboard) {
            let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
            let request = BrowserRequest {
                fetch_site: text(FETCH_SITE_HEADER),
                origin: text(header::ORIGIN.as_str()),
            };
            return if !mutation || request.is_same_origin(site) {
                Ok(())
            } else {
                Err(HttpSecurityError::ForeignForm)
            };
        }
        let origin_present = headers
            .get(header::ORIGIN)
            .is_some_and(|origin| origin.to_str().is_ok());
        if origin_present && !allowed {
            return Err(HttpSecurityError::ForbiddenOrigin);
        }
        if mutation && !allowed {
            return Err(HttpSecurityError::MissingOrigin);
        }
        if mutation && !headers.contains_key(CSRF_HEADER) {
            return Err(HttpSecurityError::MissingCsrf);
        }
        Ok(())
    }

    /// Adds the enforced [`CacheClass`] and browser isolation headers, plus the CORS
    /// `grant` when set. A cacheable response is the same for every origin, so public
    /// data is granted to all origins and other cached responses to none.
    pub(super) fn decorate(response: &mut Response, grant: Option<CorsGrant>) {
        let class = CacheClass::enforced(response);
        let grant = match class {
            CacheClass::NoStore => grant,
            CacheClass::Public { .. } => Some(CorsGrant::Public),
            // Pictures are public; the build assets need no grant.
            CacheClass::Immutable => grant.filter(|grant| matches!(grant, CorsGrant::Public)),
        };
        let headers = response.headers_mut();
        // Replaces any handler value: only the class decides.
        headers.insert(header::CACHE_CONTROL, class.cache_control());
        for (name, value) in [
            // No MIME sniffing.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // Navigation must not leak authentication URLs.
            (header::REFERRER_POLICY, "no-referrer"),
            // Authentication pages must never be framed.
            (header::X_FRAME_OPTIONS, "DENY"),
            // Keep later visits on HTTPS for a year.
            (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let (origin, allowed_headers, methods) = match grant {
            None => return,
            Some(CorsGrant::Public) => {
                for (name, value) in [
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"),
                ] {
                    headers.insert(name, HeaderValue::from_static(value));
                }
                return;
            }
            Some(CorsGrant::Client(origin)) => {
                (origin, "content-type, authorization", "GET, POST, OPTIONS")
            }
            Some(CorsGrant::Related(origin)) => {
                (origin, "content-type, x-piquel-csrf", "POST, OPTIONS")
            }
        };
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        for (name, value) in [
            (header::ACCESS_CONTROL_ALLOW_HEADERS, allowed_headers),
            (header::ACCESS_CONTROL_ALLOW_METHODS, methods),
            (header::VARY, "Origin"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        // Lets cross-origin callers, such as public clients, read the trace ID of a
        // failed request, and when a refused one may try again.
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HttpTelemetry::TRACE_ID_HEADER.into(),
        );
        headers.append(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("retry-after"),
        );
    }
}
