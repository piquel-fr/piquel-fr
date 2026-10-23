//! One server span, access log line and duration measurement per request.

use crate::{Histogram, Telemetry};
use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderName, HeaderValue, Method},
    middleware::Next,
    response::Response,
};
use opentelemetry::KeyValue;
use std::time::Instant;
use tracing::{Instrument, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Bucket boundaries in seconds the HTTP semantic conventions recommend.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// Methods the conventions name; any other is `_OTHER`, so methods stay bounded.
const METHODS: [(Method, &str); 9] = [
    (Method::GET, "GET"),
    (Method::HEAD, "HEAD"),
    (Method::POST, "POST"),
    (Method::PUT, "PUT"),
    (Method::DELETE, "DELETE"),
    (Method::CONNECT, "CONNECT"),
    (Method::OPTIONS, "OPTIONS"),
    (Method::TRACE, "TRACE"),
    (Method::PATCH, "PATCH"),
];

/// How long requests take, until the response head is ready. Labelled by method,
/// route template and status: route templates come from the router's own table and
/// unmatched paths have none, so the label set stays bounded.
static REQUEST_DURATION: Histogram = Histogram::new(
    "http.server.request.duration",
    "s",
    "Duration of HTTP server requests.",
    DURATION_BUCKETS,
);

/// Traces, measures and logs every request of a router. Wrap the whole router,
/// outside any layer that can reject a request, so rejections count too:
/// `HttpTelemetry::default().quiet(&["/health"]).wrap(router)`.
///
/// Each request gets a root span named after its method and route template, with
/// the HTTP semantic conventions' `http.request.method`, `http.route` (or
/// `url.path` when no route matched) and `http.response.status_code`. Query strings
/// and headers are never recorded. A 5xx response marks the span failed and
/// carries its trace ID in [`Self::TRACE_ID_HEADER`].
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpTelemetry {
    /// Routes whose access log lines are debug output only, such as health probes.
    quiet: &'static [&'static str],
    /// Names the listener when a service has several, as `piquel.listener`.
    listener: Option<&'static str>,
}

impl HttpTelemetry {
    /// Response header with the trace ID of a failed request, so a report can be
    /// matched to its trace. Browsers read it only where CORS exposes it.
    pub const TRACE_ID_HEADER: HeaderName = HeaderName::from_static("x-trace-id");

    /// Logs requests to `routes` at debug level only; they are still traced and measured.
    #[must_use]
    pub const fn quiet(self, routes: &'static [&'static str]) -> Self {
        Self {
            quiet: routes,
            ..self
        }
    }

    /// Labels the requests' spans, log lines and measurements with
    /// `piquel.listener = name`, telling apart the listeners of one service.
    #[must_use]
    pub const fn listener(self, name: &'static str) -> Self {
        Self {
            listener: Some(name),
            ..self
        }
    }

    /// Wraps every route and the fallback of `router`.
    pub fn wrap<S: Clone + Send + Sync + 'static>(self, router: Router<S>) -> Router<S> {
        router.layer(axum::middleware::from_fn_with_state(self, Self::trace))
    }

    /// Runs the request in its span, then records its outcome.
    async fn trace(State(this): State<Self>, request: Request, next: Next) -> Response {
        let started = Instant::now();
        let method = METHODS
            .iter()
            .find(|(known, _)| known == request.method())
            .map_or("_OTHER", |(_, name)| name);
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|path| path.as_str().to_owned());
        let span = tracing::info_span!(
            parent: None,
            "http.server",
            trace_id = Empty,
            otel.name = route.as_ref().map_or_else(|| method.to_owned(), |route| format!("{method} {route}")),
            otel.kind = "server",
            otel.status_code = Empty,
        );
        let trace_id = Telemetry::trace_id(&span);
        if let Some(trace_id) = trace_id {
            span.record("trace_id", tracing::field::display(trace_id));
        }
        let mut labels = vec![KeyValue::new("http.request.method", method)];
        labels.extend(
            this.listener
                .map(|listener| KeyValue::new("piquel.listener", listener)),
        );
        // Unmatched paths go on the span and log line only: they are unbounded.
        let path = route.is_none().then(|| request.uri().path().to_owned());
        match (&route, &path) {
            (Some(route), _) => labels.push(KeyValue::new("http.route", route.clone())),
            (None, Some(path)) => span.set_attribute("url.path", path.clone()),
            (None, None) => {}
        }
        let mut response = next.run(request).instrument(span.clone()).await;
        let status = i64::from(response.status().as_u16());
        labels.push(KeyValue::new("http.response.status_code", status));
        for label in &labels {
            span.set_attribute(label.key.clone(), label.value.clone());
        }
        if response.status().is_server_error() {
            span.record("otel.status_code", "ERROR");
            if let Some(value) = trace_id.and_then(|id| HeaderValue::try_from(id.to_string()).ok())
            {
                response.headers_mut().insert(Self::TRACE_ID_HEADER, value);
            }
        }
        let elapsed = started.elapsed();
        REQUEST_DURATION.record_attributes(elapsed.as_secs_f64(), &labels);
        let duration_ms = elapsed.as_millis();
        let quiet = route
            .as_deref()
            .is_some_and(|route| this.quiet.contains(&route));
        // Entered, so the exported log record carries the span's trace context.
        span.in_scope(|| {
            // e.g. `GET /account/passkeys/{id}`: the route template, or the
            // path when no route matched, never the query.
            let target = route.as_deref().or(path.as_deref()).unwrap_or_default();
            macro_rules! access {
                ($level:ident) => {
                    tracing::$level!(
                        http.response.status_code = status,
                        piquel.listener = this.listener,
                        duration_ms,
                        "{method} {target}"
                    )
                };
            }
            if quiet {
                access!(debug);
            } else {
                access!(info);
            }
        });
        response
    }
}

#[cfg(test)]
mod tests {
    //! What the HTTP layer records of a request.
    use super::*;
    use axum::{body::Body, http::StatusCode, routing::get};
    use tower::ServiceExt;

    /// Sends `uri` to a router with one route that fails.
    async fn send(uri: &str) -> Response {
        let router = HttpTelemetry::default().wrap(Router::new().route(
            "/items/{id}",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        ));
        router
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    /// A matched request is named by its route template and never records its
    /// query; a failure is marked and returns its trace ID.
    #[tokio::test]
    async fn spans_name_the_route_and_mark_failures() {
        let capture = Telemetry::capture("info");
        let response = send("/items/secret-id?token=secret-token").await;
        let span = capture.spans().pop().expect("server span");
        assert_eq!(span.name, "GET /items/{id}");
        assert_eq!(
            response.headers()[HttpTelemetry::TRACE_ID_HEADER],
            span.span_context.trace_id().to_string()
        );
        assert!(matches!(
            span.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        let exported = capture.exported_text();
        assert!(exported.contains(&"http.route=/items/{id}".to_owned()));
        assert!(exported.iter().all(|text| !text.contains("secret")));
    }

    /// An unmatched request records only its path, without the query.
    #[tokio::test]
    async fn unmatched_requests_record_their_path() {
        let capture = Telemetry::capture("info");
        let response = send("/missing?token=secret-token").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            !response
                .headers()
                .contains_key(HttpTelemetry::TRACE_ID_HEADER)
        );
        let span = capture.spans().pop().expect("server span");
        assert_eq!(span.name, "GET");
        let exported = capture.exported_text();
        assert!(exported.contains(&"url.path=/missing".to_owned()));
        assert!(exported.iter().all(|text| !text.contains("secret")));
    }
}
