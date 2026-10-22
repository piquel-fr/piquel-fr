# Telemetry

Auth and the admin dashboard log to stderr. When `OTEL_EXPORTER_OTLP_ENDPOINT`
is set, they also export traces, metrics and logs over OTLP/HTTP, to the
`telemetry` application in production (see "Telemetry" in
[infra/README.md](../../infra/README.md)). `piquel-telemetry`
(`crates/telemetry`) does both. A feature gets most of its telemetry for free and
adds the rest in one line.

## What every feature gets

- **A trace per request and job run.** `HttpTelemetry` wraps both of auth's
  routers and the dashboard's. Each request gets one root span, named after its
  method and route template (`POST /oauth/token`). Every log line inside the
  span carries the trace ID, on stderr and in exported logs. Exclusive jobs get
  one root span per run. Incoming `traceparent` headers are ignored: a public
  caller must not choose the trace IDs that events keep.
- **An access log line** with status and duration. Health probes log at debug
  level only.
- **A span per query.** `run!` wraps every query in a `db.query` span with its
  parameterized SQL (`db.query.text`), never its bind values.
- **Events in telemetry.** Every event recorded with `DatabaseTransaction::record`
  stores the current trace ID in `domain_events.trace_id`, and once its
  transaction commits it is logged as `event recorded` (with its ID, kind, kind
  of actor and subject) and counted in `piquel.auth.events{kind}`. The audit
  history and telemetry therefore point at each other: the admin dashboard shows
  each event's trace ID, and the trace shows each event its request recorded. A
  rolled-back transaction counts nothing. Telemetry is best effort, though: a
  request cancelled while its `COMMIT` is in flight can commit an event that is
  never logged or counted. The stored history is the audit record.
- **Failures.** A 5xx response marks its span failed and returns the trace ID in
  `X-Trace-Id`, which CORS exposes to the frontends. `tracing::error!` events
  with an `error` field, such as `ApiError::log_error`'s, also mark their span.

## Adding telemetry

**A log line or span:** the `tracing` macros. Auth's own targets
(`auth_service`, `piquel_repository`) are traced and logged at `info`; use
`debug!` for detail nobody needs in production.

**A count derived from an event:** add an arm to `Committed::publish` in
`crates/database/src/telemetry.rs`. Counting there, after the commit, never
counts a change that rolled back.

**Any other metric:** a `static` instrument next to the code it measures:

```rust
/// Requests refused because their client's budget was exhausted, by category.
static THROTTLED: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.throttled",
    "{request}",
    "Requests refused by rate limits, by rate category.",
);

THROTTLED.add(1, &[("category", category.as_str())]);
```

`Counter`, `Histogram` and `Gauge` take their labels as `Labels`: a type per
instrument, such as `[Label; N]` or a struct. A label value is a
`&'static str`, so a user, client, session ID or IP address cannot become one.
That keeps metrics free of personal data and their cardinality bounded. Name
instruments after the [semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
where one exists, and `piquel.auth.*` otherwise. Units follow UCUM: `s`, or
`{thing}` for counts.

**An outbound HTTP call:** `request.send_traced()` instead of `send()`. It
records the method, host and status only.

## What never goes in telemetry

Everything a span, log line or label holds is exported. Never record a secret
(cookie, code, token, ceremony state, invitation, client secret), a query string,
a request header, a client IP or a user agent. Events keep IPs and user agents
under their own retention rules. User IDs are pseudonymous, so they are allowed
on spans and log lines. The collector also deletes `url.query`, `url.full`,
`client.address` and `http.*.header.*` attributes, as a second line of defense.

`passkey::tests::telemetry_exports_no_secret_of_a_sign_in_and_code_exchange`
runs a passkey sign-in and a code exchange through the production layers, with
`Telemetry::capture`, and fails if any of their secrets is exported. Extend it
when a flow handles a new kind of secret.

## Configuration

Only the standard variables, read by `Telemetry::init`:

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL, e.g. `http://collector.telemetry:4318`; unset or empty exports nothing |
| `OTEL_SDK_DISABLED` | `true` keeps telemetry on stderr only |
| `OTEL_SERVICE_NAME` | Overrides `auth-service` or `admin-web` |
| `OTEL_RESOURCE_ATTRIBUTES` | e.g. `deployment.environment.name=staging`, which dashboards filter on |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampling; every trace is kept by default |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Bound on each export request, in milliseconds; 10000 by default. The per-signal variants are not supported |
| `RUST_LOG` | What is logged; spans keep the service's default filter |

Export goes through the workspace's `reqwest`, on the service's tokio runtime,
in protobuf. A gRPC `OTEL_EXPORTER_OTLP_PROTOCOL` fails at startup. Shutdown
flushes pending telemetry after the listeners stop.

## Locally

```sh
just infra telemetry   # Grafana, with the Auth overview dashboard, at http://localhost:3000
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=local just auth serve
```
