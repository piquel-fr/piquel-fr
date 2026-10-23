//! Client spans around outbound HTTP requests.

use reqwest::{RequestBuilder, Response};
use tracing::{Instrument, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Sends a `reqwest` request in a client span, e.g. `client.get(url).send_traced()`.
pub trait SendTraced {
    /// Sends the request in a span recording only its method, host and response
    /// status: never its path, query, headers or body, which carry codes and tokens.
    /// A failure or 4xx/5xx status marks the span failed.
    fn send_traced(self) -> impl Future<Output = reqwest::Result<Response>> + Send;
}

impl SendTraced for RequestBuilder {
    async fn send_traced(self) -> reqwest::Result<Response> {
        let (client, request) = self.build_split();
        let request = request?;
        let method = request.method().as_str().to_owned();
        let span = tracing::info_span!(
            "http.client",
            otel.name = method,
            otel.kind = "client",
            otel.status_code = Empty,
        );
        span.set_attribute("http.request.method", method);
        if let Some(host) = request.url().host_str() {
            span.set_attribute("server.address", host.to_owned());
        }
        let response = client.execute(request).instrument(span.clone()).await;
        match &response {
            Ok(response) => {
                span.set_attribute(
                    "http.response.status_code",
                    i64::from(response.status().as_u16()),
                );
                if response.status().is_client_error() || response.status().is_server_error() {
                    span.record("otel.status_code", "ERROR");
                }
            }
            Err(_) => {
                span.record("otel.status_code", "ERROR");
            }
        }
        response
    }
}
