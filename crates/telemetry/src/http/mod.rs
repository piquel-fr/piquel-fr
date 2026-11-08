//! One server span, access log line and duration measurement per request.

use crate::{Histogram, Telemetry};
use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use opentelemetry::KeyValue;
use piquel_common::TraceId;
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

/// Stands for the path of a request that matched no route, in its access log
/// line. The path itself is never recorded: it is whatever the client sent, such
/// as a mistyped link with an address in it.
const UNMATCHED: &str = "unmatched";

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
/// the HTTP semantic conventions' `http.request.method`, `http.route` (absent when
/// no route matched) and `http.response.status_code`. Paths, query strings and
/// headers are never recorded. A 5xx response marks the span failed and
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

    /// The trace ID that a response at `status`, answered from within its request,
    /// carries in [`Self::TRACE_ID_HEADER`]: a server error's, and no other. A page
    /// shows it too, since a browser never shows the header.
    #[must_use]
    pub fn trace_id(status: StatusCode) -> Option<TraceId> {
        status
            .is_server_error()
            .then(Telemetry::current_trace_id)
            .flatten()
    }

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
        labels.extend(
            route
                .as_ref()
                .map(|route| KeyValue::new("http.route", route.clone())),
        );
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
            // e.g. `GET /account/passkeys/{id}`: the route template, never the
            // path or query.
            let target = route.as_deref().unwrap_or(UNMATCHED);
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
mod tests;
