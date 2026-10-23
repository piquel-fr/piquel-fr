//! What a test would export, captured in memory through the production layers.

use crate::Telemetry;
use opentelemetry_sdk::{
    logs::{InMemoryLogExporter, SdkLogRecord, SdkLoggerProvider},
    trace::{InMemorySpanExporter, SdkTracerProvider, SpanData},
};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::util::SubscriberInitExt;

/// Spans and logs exported on this thread since [`Telemetry::capture`], until dropped.
pub struct Capture {
    /// Receives each span as it ends.
    spans: InMemorySpanExporter,
    /// Receives each log record as it is emitted.
    logs: InMemoryLogExporter,
    /// Keeps the tracer alive.
    _tracer: SdkTracerProvider,
    /// Keeps the logger alive.
    _logger: SdkLoggerProvider,
    /// Uninstalls the subscriber when dropped.
    _guard: DefaultGuard,
}

impl Telemetry {
    /// Captures what this thread exports until the result drops, filtered by
    /// `default_filter` as [`Self::init`] would. A test on a current-thread
    /// runtime captures every request it sends to an in-process router.
    ///
    /// # Panics
    /// Panics if `default_filter` does not parse.
    #[must_use]
    pub fn capture(default_filter: &str) -> Capture {
        let spans = InMemorySpanExporter::default();
        let logs = InMemoryLogExporter::default();
        let tracer = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let logger = SdkLoggerProvider::builder()
            .with_simple_exporter(logs.clone())
            .build();
        let guard = Self::subscriber(&tracer, Some(&logger), default_filter, None)
            .expect("valid default filter")
            .set_default();
        Capture {
            spans,
            logs,
            _tracer: tracer,
            _logger: logger,
            _guard: guard,
        }
    }
}

impl Capture {
    /// Every finished span.
    ///
    /// # Panics
    /// Panics if the exporter's lock is poisoned.
    #[must_use]
    pub fn spans(&self) -> Vec<SpanData> {
        self.spans.get_finished_spans().expect("captured spans")
    }

    /// Every emitted log record.
    ///
    /// # Panics
    /// Panics if the exporter's lock is poisoned.
    #[must_use]
    pub fn logs(&self) -> Vec<SdkLogRecord> {
        self.logs
            .get_emitted_logs()
            .expect("captured logs")
            .into_iter()
            .map(|log| log.record)
            .collect()
    }

    /// Every exported string: span names, attributes and events, and log bodies
    /// and attributes, each as `key=value` where it has a key.
    ///
    /// # Panics
    /// Panics if an exporter's lock is poisoned.
    #[must_use]
    pub fn exported_text(&self) -> Vec<String> {
        let mut text = Vec::new();
        for span in self.spans() {
            text.push(span.name.to_string());
            text.extend(
                span.attributes
                    .iter()
                    .map(|attribute| format!("{}={}", attribute.key, attribute.value)),
            );
            for event in span.events.iter() {
                text.push(event.name.to_string());
                text.extend(
                    event
                        .attributes
                        .iter()
                        .map(|attribute| format!("{}={}", attribute.key, attribute.value)),
                );
            }
        }
        for log in self.logs() {
            text.extend(log.body().map(|body| format!("{body:?}")));
            text.extend(
                log.attributes_iter()
                    .map(|(key, value)| format!("{key}={value:?}")),
            );
        }
        text
    }
}
