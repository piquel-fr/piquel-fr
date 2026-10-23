//! Telemetry for service executables: logs on stderr always, and OpenTelemetry
//! traces, metrics and logs over OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//!
//! Features use it four ways:
//!
//! - **Spans and logs:** the `tracing` macros. Every request and job run has a
//!   trace, and each log line inside it carries its trace ID, on stderr and in
//!   exported logs.
//! - **HTTP servers:** [`HttpTelemetry`] gives each request of a router one server
//!   span, an access log line and the `http.server.request.duration` histogram.
//! - **HTTP clients:** [`SendTraced::send_traced`] sends a `reqwest` request in a
//!   client span.
//! - **Metrics:** a `static` [`Counter`], [`Histogram`] or [`Gauge`], labelled with
//!   [`Labels`] whose values are `&'static str`, so no ID, name or address can
//!   label a metric.
//!
//! Everything a span, log line or label holds may be exported. Never record a
//! secret, a query string or a request header.

/// Client spans for outbound `reqwest` requests.
mod client;
/// OTLP export through the workspace's `reqwest`.
mod export;
/// Server spans, access logs and request durations for axum routers.
mod http;
/// Instruments declared as `static`s.
mod metrics;

/// In-memory capture of what tests would export.
#[cfg(any(test, feature = "test-util"))]
mod capture;

#[cfg(any(test, feature = "test-util"))]
pub use capture::Capture;
pub use client::SendTraced;
pub use http::HttpTelemetry;
pub use metrics::{Counter, Gauge, Histogram, Label, Labels};

use export::Exporters;
use opentelemetry::{KeyValue, trace::TraceContextExt};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::ExporterBuildError;
use opentelemetry_sdk::{
    Resource, error::OTelSdkError, logs::SdkLoggerProvider, metrics::SdkMeterProvider,
    trace::SdkTracerProvider,
};
use piquel_common::{
    TraceId,
    config::{ConfigurationError, Variable},
};
use std::io::IsTerminal;
use thiserror::Error;
use tracing::{Metadata, Subscriber, subscriber::Interest};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{
    EnvFilter, Layer,
    field::{RecordFields, Visit},
    filter::{FilterFn, LevelFilter, ParseError},
    fmt::{FormatFields, format::Writer},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use uuid::Uuid;

/// Instrumentation scope of every tracer and meter.
const SCOPE: &str = "piquel";
/// Added to every filter: this crate's spans and access logs, and the SDK's own
/// warnings, such as failed exports.
const OWN_DIRECTIVES: &str = "piquel_telemetry=info,opentelemetry=warn";
/// Targets never exported as logs: the SDK, which logs its own failures, and the
/// HTTP stack export requests run on, outside the SDK's suppression of its own
/// telemetry. Exporting either would feed the exporter its own traffic. They still
/// log to stderr.
const UNEXPORTED_TARGETS: [&str; 5] = ["opentelemetry", "reqwest", "hyper", "h2", "rustls"];
/// `true` keeps telemetry on stderr only, as the SDK specification says.
const SDK_DISABLED: Variable = Variable::new("OTEL_SDK_DISABLED");
/// Where OTLP is sent; unset or empty means nothing is exported.
const ENDPOINT: Variable = Variable::new("OTEL_EXPORTER_OTLP_ENDPOINT");
/// Resource attribute naming the service.
const SERVICE_NAME: &str = "service.name";
/// Resource attribute naming this process, so replicas and command-line runs of
/// one service each keep their own metric series.
const INSTANCE_ID: &str = "service.instance.id";

/// Failures installing or flushing telemetry.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The service's default log filter does not parse.
    #[error("invalid default log filter")]
    Filter(#[from] ParseError),
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_SDK_DISABLED` is invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// `init` was called outside a tokio runtime, which sends OTLP.
    #[error("telemetry export needs a tokio runtime")]
    Runtime(#[from] tokio::runtime::TryCurrentError),
    /// An `OTEL_EXPORTER_OTLP_*` variable is invalid, e.g. a gRPC protocol.
    #[error("could not configure OTLP export")]
    Exporter(#[from] ExporterBuildError),
    /// The HTTP client sending OTLP could not be built.
    #[error("could not build the OTLP HTTP client")]
    Client(#[from] reqwest::Error),
    /// Another subscriber is already installed.
    #[error("a tracing subscriber is already installed")]
    Installed(#[from] tracing_subscriber::util::TryInitError),
    /// Pending telemetry could not be flushed at shutdown.
    #[error("could not flush telemetry")]
    Flush(#[from] OTelSdkError),
    /// The flush panicked.
    #[error("telemetry flush panicked")]
    Join(#[from] tokio::task::JoinError),
}

/// A service's installed telemetry. Spans always get trace IDs; exporters exist
/// only while `OTEL_EXPORTER_OTLP_ENDPOINT` is set and `OTEL_SDK_DISABLED` is not
/// `true` (it must be `true` or `false`). `OTEL_EXPORTER_OTLP_TIMEOUT` bounds each
/// export request. The SDK reads the others: `OTEL_SERVICE_NAME`,
/// `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER` and its `_ARG`, and
/// `OTEL_EXPORTER_OTLP_HEADERS`.
///
/// Incoming `traceparent` headers are ignored: a public caller must not choose the
/// trace IDs that recorded events keep.
#[must_use = "call `shutdown` to flush pending telemetry"]
pub struct Telemetry {
    /// Assigns trace IDs, and exports spans when exporting.
    tracer: SdkTracerProvider,
    /// Exports metrics, when exporting.
    meter: Option<SdkMeterProvider>,
    /// Exports logs, when exporting.
    logger: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// Installs telemetry for `service`, the default `service.name`. Logs are
    /// filtered by `RUST_LOG`, or else `default_filter`; spans always by
    /// `default_filter`, so quieter logs never lose traces. Call it first, inside
    /// the tokio runtime: instruments used before bind to no provider.
    ///
    /// # Errors
    /// Fails on an invalid filter or `OTEL_*` variable, outside a tokio runtime, or
    /// when a subscriber is already installed.
    pub fn init(service: &'static str, default_filter: &str) -> Result<Self, TelemetryError> {
        let resource = Self::resource(service);
        let mut tracer = SdkTracerProvider::builder().with_resource(resource.clone());
        let mut telemetry = Self {
            tracer: SdkTracerProvider::default(),
            meter: None,
            logger: None,
        };
        if let Some(exporters) = Self::exporting()?.then(Exporters::new).transpose()? {
            tracer = tracer.with_batch_exporter(exporters.spans);
            let meter = SdkMeterProvider::builder()
                .with_resource(resource.clone())
                .with_periodic_exporter(exporters.metrics)
                .build();
            opentelemetry::global::set_meter_provider(meter.clone());
            telemetry.meter = Some(meter);
            telemetry.logger = Some(
                SdkLoggerProvider::builder()
                    .with_resource(resource)
                    .with_batch_exporter(exporters.logs)
                    .build(),
            );
        }
        telemetry.tracer = tracer.build();
        Self::subscriber(
            &telemetry.tracer,
            telemetry.logger.as_ref(),
            default_filter,
            EnvFilter::try_from_default_env().ok(),
        )?
        .try_init()?;
        Ok(telemetry)
    }

    /// Flushes and stops every exporter; call it once the service stopped serving.
    ///
    /// # Errors
    /// Returns the first provider that failed to flush.
    pub async fn shutdown(self) -> Result<(), TelemetryError> {
        // Exporters send on this runtime while the flush blocks its own thread.
        tokio::task::spawn_blocking(move || {
            let tracer = self.tracer.shutdown();
            let meter = self.meter.map_or(Ok(()), |meter| meter.shutdown());
            let logger = self.logger.map_or(Ok(()), |logger| logger.shutdown());
            tracer.and(meter).and(logger)
        })
        .await??;
        Ok(())
    }

    /// The trace ID of the current span, e.g. to keep with what a request records.
    #[must_use]
    pub fn current_trace_id() -> Option<TraceId> {
        Self::trace_id(&tracing::Span::current())
    }

    /// The trace ID of `span`, unless telemetry is not installed or filters it out.
    fn trace_id(span: &tracing::Span) -> Option<TraceId> {
        let context = span.context();
        let span = context.span();
        let span = span.span_context();
        span.is_valid()
            .then(|| TraceId::from_bytes(span.trace_id().to_bytes()))
            .flatten()
    }

    /// Whether OTLP export is configured and not disabled.
    fn exporting() -> Result<bool, TelemetryError> {
        let endpoint = ENDPOINT
            .optional()?
            .is_some_and(|endpoint| !endpoint.trim().is_empty());
        Ok(endpoint && !SDK_DISABLED.flag(false)?)
    }

    /// The SDK's resource from `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`,
    /// named `service` when neither names it, and with a new UUID as this
    /// process's `service.instance.id` unless they give one.
    fn resource(service: &'static str) -> Resource {
        let detected = Resource::builder().build();
        let named = detected
            .get(&SERVICE_NAME.into())
            .is_some_and(|name| !name.as_str().starts_with("unknown_service"));
        let mut defaults = Vec::new();
        if !named {
            defaults.push(KeyValue::new(SERVICE_NAME, service));
        }
        if detected.get(&INSTANCE_ID.into()).is_none() {
            defaults.push(KeyValue::new(INSTANCE_ID, Uuid::now_v7().to_string()));
        }
        Resource::builder().with_attributes(defaults).build()
    }

    /// The layers `init` installs: spans to `tracer`, filtered by `default_filter`;
    /// compact stderr lines and, with a `logger`, exported logs, filtered by
    /// `logs` or else `default_filter`. Tests capture through the same layers.
    fn subscriber(
        tracer: &SdkTracerProvider,
        logger: Option<&SdkLoggerProvider>,
        default_filter: &str,
        logs: Option<EnvFilter>,
    ) -> Result<impl Subscriber + Send + Sync + 'static, TelemetryError> {
        let directives = format!("{default_filter},{OWN_DIRECTIVES}");
        let logs = match logs {
            Some(logs) => logs,
            None => EnvFilter::try_new(&directives)?,
        };
        let spans = tracing_opentelemetry::layer()
            .with_tracer(opentelemetry::trace::TracerProvider::tracer(tracer, SCOPE))
            .with_filter(EnvFilter::try_new(&directives)?);
        let exported = logger.map(|logger| {
            OpenTelemetryTracingBridge::new(logger).with_filter(FilterFn::new(|metadata| {
                !UNEXPORTED_TARGETS
                    .iter()
                    .any(|target| metadata.target().starts_with(target))
            }))
        });
        let stderr = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .with_target(false)
            .compact()
            .fmt_fields(StderrFields);
        Ok(tracing_subscriber::registry()
            .with(spans)
            .with(stderr.and_then(exported).with_filter(logs))
            .with(Recheck))
    }
}

/// Makes every callsite ask the filters each time. Per-layer filters keep their
/// decisions in a thread-local that only such a check overwrites, and a callsite
/// cached as always enabled skips it. It would read what a check no event followed
/// left, e.g. `LogTracer`'s for a dependency's `log::log_enabled!`, and reach no
/// layer: a span lost that way splits its trace.
struct Recheck;

impl<S: Subscriber> Layer<S> for Recheck {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    /// No opinion: the filters below decide the most verbose level.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::OFF)
    }
}

/// Formats the fields of stderr lines as `key=value`, leaving out `otel.*`: those
/// only name and type exported spans.
struct StderrFields;

impl<'writer> FormatFields<'writer> for StderrFields {
    fn format_fields<R: RecordFields>(
        &self,
        writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        let mut visitor = StderrVisitor {
            writer,
            separator: "",
            result: Ok(()),
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

/// Writes one line's fields, separated by spaces.
struct StderrVisitor<'writer> {
    /// The line.
    writer: Writer<'writer>,
    /// Written before the next field: nothing before the first.
    separator: &'static str,
    /// The first write failure.
    result: std::fmt::Result,
}

impl Visit for StderrVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let separator = self.separator;
        let written = match field.name() {
            name if name.starts_with("otel.") => return,
            "message" => write!(self.writer, "{separator}{value:?}"),
            name => write!(self.writer, "{separator}{name}={value:?}"),
        };
        self.separator = " ";
        self.result = self.result.and(written);
    }
}

#[cfg(test)]
mod tests {
    //! How the installed layers filter.
    use super::*;
    use tracing::{Callsite, Level, metadata::Kind};

    /// A span right after a check that no event followed is still exported, as
    /// after `log::log_enabled!` in a dependency, which `LogTracer` forwards.
    #[test]
    fn a_span_after_a_refused_check_is_exported() {
        let capture = Telemetry::capture("piquel_telemetry=info");
        let refused = tracing::callsite!(
            name: "refused",
            kind: Kind::EVENT,
            target: "elsewhere",
            level: Level::INFO,
            fields: []
        );
        tracing::dispatcher::get_default(|dispatch| dispatch.enabled(refused.metadata()));
        drop(tracing::info_span!("exported"));
        let spans = capture.spans();
        assert_eq!(
            spans
                .iter()
                .map(|span| span.name.as_ref())
                .collect::<Vec<_>>(),
            ["exported"]
        );
    }
}
