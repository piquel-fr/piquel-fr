//! Client spans around outbound HTTP requests.

use reqwest::{RequestBuilder, Response};
use tracing::{Instrument, field::Empty};

/// Sends a `reqwest` request in a client span, e.g. `client.get(url).send_traced()`.
/// Auth's provider and delivery calls use it, and so does the Rust SDK, so every
/// request either sends looks the same in a trace.
pub trait SendTraced {
    /// Sends the request in an `http.client` span, at `info` under the
    /// `piquel_common` target, recording only its method, host and response status
    /// as OpenTelemetry's HTTP client conventions name them: never its path, query,
    /// headers or body, which carry codes and tokens. A failure or 4xx/5xx status
    /// marks the span failed.
    fn send_traced(self) -> impl Future<Output = reqwest::Result<Response>> + Send;
}

impl SendTraced for RequestBuilder {
    async fn send_traced(self) -> reqwest::Result<Response> {
        let (client, request) = self.build_split();
        let request = request?;
        let method = request.method().as_str();
        let span = tracing::info_span!(
            "http.client",
            otel.name = method,
            otel.kind = "client",
            otel.status_code = Empty,
            http.request.method = method,
            server.address = request.url().host_str(),
            http.response.status_code = Empty,
        );
        let response = client.execute(request).instrument(span.clone()).await;
        match &response {
            Ok(response) => {
                // tracing-opentelemetry exports unsigned integers as strings.
                span.record(
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
