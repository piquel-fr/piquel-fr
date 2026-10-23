//! OTLP/HTTP exporters sending protobuf through the workspace's `reqwest`.

use crate::TelemetryError;
use async_trait::async_trait;
use bytes::Bytes;
use opentelemetry_http::{HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithHttpConfig};
use piquel_common::config::Variable;
use std::{sync::Arc, time::Duration};
use tokio::runtime::Handle;

/// Bound on one export request in milliseconds, which only this client enforces.
/// The per-signal `OTEL_EXPORTER_OTLP_*_TIMEOUT` variables are not supported.
const TIMEOUT: Variable = Variable::new("OTEL_EXPORTER_OTLP_TIMEOUT");
/// The specification's default [`TIMEOUT`].
const DEFAULT_TIMEOUT_MS: &str = "10000";

/// One exporter per signal, sharing one HTTP client.
pub(crate) struct Exporters {
    /// Sends spans to `/v1/traces`.
    pub(crate) spans: SpanExporter,
    /// Sends metrics to `/v1/metrics`.
    pub(crate) metrics: MetricExporter,
    /// Sends logs to `/v1/logs`.
    pub(crate) logs: LogExporter,
}

impl Exporters {
    /// Builds the exporters from the `OTEL_EXPORTER_OTLP_*` variables, sending on
    /// the current tokio runtime.
    pub(crate) fn new() -> Result<Self, TelemetryError> {
        let client: Arc<dyn HttpClient> = Arc::new(Transport {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(TIMEOUT.parse_or(DEFAULT_TIMEOUT_MS)?))
                .build()?,
            runtime: Handle::try_current()?,
        });
        Ok(Self {
            spans: SpanExporter::builder()
                .with_http()
                .with_shared_http_client(Arc::clone(&client))
                .build()?,
            metrics: MetricExporter::builder()
                .with_http()
                .with_shared_http_client(Arc::clone(&client))
                .build()?,
            logs: LogExporter::builder()
                .with_http()
                .with_shared_http_client(client)
                .build()?,
        })
    }
}

/// Sends export requests on the service's tokio runtime. The SDK exports from
/// threads of its own, which have no runtime for `reqwest` to run on.
#[derive(Debug)]
struct Transport {
    /// Sends the requests.
    client: reqwest::Client,
    /// The runtime the requests run on.
    runtime: Handle,
}

#[async_trait]
impl HttpClient for Transport {
    /// Sends `request` and buffers the collector's response.
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let client = self.client.clone();
        self.runtime
            .spawn(async move {
                let response = client.execute(request.try_into()?).await?;
                let mut answer = Response::builder().status(response.status());
                if let Some(headers) = answer.headers_mut() {
                    headers.extend(response.headers().clone());
                }
                Ok(answer.body(response.bytes().await?)?)
            })
            .await?
    }
}
