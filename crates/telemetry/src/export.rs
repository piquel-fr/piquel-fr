//! OTLP/HTTP exporters sending protobuf through the workspace's `reqwest`.

use async_trait::async_trait;
use bytes::Bytes;
use opentelemetry_http::{HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{
    ExporterBuildError, LogExporter, MetricExporter, SpanExporter, WithHttpConfig,
};
use sourceorigin_common::config::{ConfigurationError, Variable};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::runtime::{Handle, TryCurrentError};

/// `true` keeps telemetry on stderr only, as the SDK specification says.
const SDK_DISABLED: Variable = Variable::new("OTEL_SDK_DISABLED");
/// Where OTLP is sent; unset or empty means nothing is exported.
const ENDPOINT: Variable = Variable::new("OTEL_EXPORTER_OTLP_ENDPOINT");
/// Bound on one export request in milliseconds, which only this client enforces.
/// The per-signal `OTEL_EXPORTER_OTLP_*_TIMEOUT` variables are not supported.
const TIMEOUT: Variable = Variable::new("OTEL_EXPORTER_OTLP_TIMEOUT");
/// The specification's default [`TIMEOUT`].
const DEFAULT_TIMEOUT_MS: &str = "10000";

/// What [`Telemetry::init`](crate::Telemetry::init) does when OTLP export is
/// configured but cannot start, such as on a malformed endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
    /// Fail: a server must not run without the telemetry its alerts read, so a
    /// broken configuration stops the deployment instead.
    Required,
    /// Log to stderr only, with a warning: a command-line run, such as a
    /// migration or an account repair, must work while telemetry is broken.
    Optional,
}

/// Why OTLP export could not start.
#[derive(Debug, Error)]
pub enum ExportError {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TIMEOUT` or
    /// `OTEL_SDK_DISABLED` is invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// Telemetry was installed outside a tokio runtime, which sends OTLP.
    #[error("telemetry export needs a tokio runtime")]
    Runtime(#[from] TryCurrentError),
    /// An `OTEL_EXPORTER_OTLP_*` variable is invalid, e.g. a malformed endpoint.
    #[error("could not configure OTLP export")]
    Exporter(#[from] ExporterBuildError),
    /// The HTTP client sending OTLP could not be built.
    #[error("could not build the OTLP HTTP client")]
    Client(#[from] reqwest::Error),
}

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
    /// The exporters, while [`ENDPOINT`] is set and [`SDK_DISABLED`] is not `true`
    /// (it must be `true` or `false`).
    pub(crate) fn from_environment() -> Result<Option<Self>, ExportError> {
        let endpoint = ENDPOINT
            .optional()?
            .is_some_and(|endpoint| !endpoint.trim().is_empty());
        if !endpoint || SDK_DISABLED.flag(false)? {
            return Ok(None);
        }
        Self::new().map(Some)
    }

    /// Builds the exporters from the `OTEL_EXPORTER_OTLP_*` variables, sending on
    /// the current tokio runtime.
    fn new() -> Result<Self, ExportError> {
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
