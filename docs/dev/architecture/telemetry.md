# Telemetry

This page explains the telemetry auth-service and sourceorigin-web produce, how to add
more, and what never goes in it.

Both services log to stderr. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, they
also export traces, metrics and logs over OTLP/HTTP, to the `sourceorigin-observability`
application in production (see [the telemetry stack](../operations/telemetry.md)).
`sourceorigin-telemetry` (`crates/telemetry`) does both. A feature gets most of its
telemetry for free and adds the rest in one line.

## What every feature gets

- **A trace per request, job run and delivery attempt.** `HttpTelemetry` wraps
  auth's public and admin routers and sourceorigin-web's, outside every layer that can
  refuse a request ([request lifecycle](request-lifecycle.md)). Each request gets one root span,
  named after its method and route template (`POST /oauth/token`). Every log line
  inside the span carries the trace ID, on stderr and in exported logs. Exclusive
  jobs get one root span per run, and delivery workers one per attempt. Incoming
  `traceparent` headers are ignored: a public caller must not choose the trace IDs
  that events keep.
- **An access log line** with status and duration, such as `GET
  /account/passkeys/{id}`. A request that matches no route logs `GET
  unmatched`: its path is whatever the client sent, so it is never recorded.
  Health probes log at debug level only.
- **A span per query.** `run!` wraps every query in a trace in a `db.query` span
  with its parameterized SQL (`db.query.text`), never its bind values. Queries
  outside a trace, such as an idle delivery worker's poll every second or a
  command-line run's, are not traced: each would be a trace of its own.
- **Events in telemetry.** Every event recorded with `DatabaseTransaction::record`
  stores the current trace ID in `domain_events.trace_id`, and once its
  transaction commits it is logged as `event recorded` (with its ID, kind, kind
  of actor, subject and, when one acted from the admin dashboard, administrator) and
  counted in `sourceorigin.auth.events{kind}`. The audit
  history and telemetry therefore point at each other: the admin dashboard shows
  each event's trace ID, and the trace shows each event its request recorded. A
  rolled-back transaction counts nothing. Telemetry is best effort, though: a
  request cancelled while its `COMMIT` is in flight can commit an event that is
  never logged or counted. The stored history is the audit record.
- **Failures.** A 5xx response marks its span failed and returns the trace ID in
  `X-Trace-Id`, which CORS exposes to public clients' origins. JSON error bodies
  do not repeat it. A page answering a server error, on auth or the admin
  dashboard, shows the same trace ID as a reference to quote in a report, since
  a browser never shows the header; no other page shows one. `tracing::error!` events with an `error` field, such as
  `ApiError::log_error`'s, also mark their span. Every request of an
  administrator the dashboard or auth's handoff page refuses is logged as `admin
  dashboard request refused`, with its `admin.failure` reason.
- **One series per process.** Each process gets a new UUID as its
  `service.instance.id`, so replicas and command-line runs never write to the
  same metric series. The admin dashboard's requests carry `sourceorigin.listener =
  "admin"`, which tells them apart from the public listener's.

## Adding telemetry

**A log line or span:** the `tracing` macros. Auth's own targets
(`auth_service`, `sourceorigin_repository`) are traced and logged at `info`; use
`debug!` for detail nobody needs in production.

**A count derived from an event:** add an arm to `Committed::publish` in
`crates/database/src/telemetry.rs`. Counting there, after the commit, never
counts a change that rolled back. Prometheus estimates counts over a range, so a
dashboard that needs exact counts of rare events, such as Admin activity,
counts their `event recorded` lines in Loki instead.

**Any other metric:** a `static` instrument next to the code it measures:

```rust
/// Requests refused because their client's budget was exhausted, by category.
static THROTTLED: Counter<[Label; 1]> = Counter::new(
    "sourceorigin.auth.throttled",
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
where one exists, and `sourceorigin.auth.*` otherwise. Units follow UCUM: `s`, or
`{thing}` for counts.

**An outbound HTTP call:** `request.send_traced()` instead of `send()`. It
records the method, host and status only. `SendTraced` lives in `sourceorigin-common`
so the Rust SDK sends its requests, such as Google's signing-key fetches through
`KeyCache`, the same way.

## What never goes in telemetry

Everything a span, log line or label holds is exported. Never record a secret
(cookie, code, token, ceremony state, invitation, client secret), a query string,
a request header, a request path, a client IP or a user agent. Events keep IPs
and user agents under their own retention rules. User IDs are pseudonymous, so
they are allowed on spans and log lines. The collector also deletes `url.path`,
`url.query`, `url.full`, `client.address` and `http.*.header.*` attributes, as a
second line of defense.

Some errors quote personal data, so they are logged with care:

- **Errors** are logged as `error = %ErrorChain(&error)`: each message of the
  chain, never a type's `Debug`. `DatabaseError`'s `Debug` is that chain too, so
  even `?error` on it, or on an error holding it, leaves out PostgreSQL's
  `detail`, which quotes the rejected values (`Key (address)=(…) already
  exists`). A stored value that does not decode keeps only its column and, for
  JSON, the failure's category and position (`DecodeFailure`), never the
  decoder's message, which can quote the value.
- **SMTP failures** keep only the reply code or failure category, as the
  delivery's error. The relay's reply text can quote the recipient, so it is
  never logged, at any level.

`passkey::tests::telemetry::telemetry_exports_no_secret_of_a_sign_in_and_code_exchange`
runs a passkey sign-in and a code exchange through the production layers, with
`Telemetry::capture`, and fails if any of their secrets is exported. Extend it
when a flow handles a new kind of secret.

## Configuration

Only the standard variables, read by `Telemetry::init`:

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL, e.g. `http://collector.sourceorigin-observability:4318`; unset or empty exports nothing |
| `OTEL_SDK_DISABLED` | `true` keeps telemetry on stderr only |
| `OTEL_SERVICE_NAME` | Overrides the default, `auth-service` or `sourceorigin-web` |
| `OTEL_RESOURCE_ATTRIBUTES` | e.g. `deployment.environment.name=staging`, which dashboards filter on |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampling; every trace is kept by default |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Bound on each export request, in milliseconds; 10000 by default. The per-signal variants are not supported |
| `RUST_LOG` | What is logged; spans keep the service's default filter. A value that does not parse stops every command |

When export is configured but cannot start, such as on a malformed endpoint,
`serve` and the web app refuse to start: a server must not run without the
telemetry its alerts read. Every other `auth-service` command, such as
`migrate` or an account repair, logs a warning and runs with logs on stderr
only, so broken telemetry never blocks a break-glass fix.

Export goes through the workspace's `reqwest`, on the service's tokio runtime,
in protobuf, whatever `OTEL_EXPORTER_OTLP_PROTOCOL` says. Shutdown flushes
pending telemetry after the listeners stop, for up to 3 seconds (see
[Stopping](../operations/deploying.md#stopping)).

## Locally

```sh
just infra telemetry   # Grafana, with both dashboards, at http://localhost:3000
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=local just auth serve
```
