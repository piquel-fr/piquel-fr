# Telemetry stack

`infra/telemetry.toml` is the `telemetry` application, with one environment,
`production`, that follows `main`:

| Service | Image | Role |
| --- | --- | --- |
| `collector` | `otel/opentelemetry-collector-contrib` | OTLP/HTTP on port 4318; memory limit, batching, and deletion of paths, query strings, headers and client addresses |
| `prometheus` | `prom/prometheus` | Metrics, received over OTLP, kept 30 days |
| `tempo` | `grafana/tempo` | Traces, kept 14 days |
| `loki` | `grafana/loki` | Logs, received over OTLP, kept 30 days |
| `grafana` | `grafana/grafana` | Dashboards at `grafana.piquel.fr` |

## Dashboards

Their configuration is in `infra/telemetry/`, mounted as piqueld files. Grafana
provisions the three data sources, linked so a log line opens its trace and a
trace its logs, and two dashboards in the `piquel.fr` folder:

- **Auth overview**: traffic, errors and latency by route, sign-ins,
  registrations, tokens, refresh revocations, throttling, events by kind, the
  database pool, cleanup, the delivery queue (pending deliveries, the oldest one's
  age and attempts by outcome, per channel; see
  [the delivery queue](../architecture/delivery-queue.md)), logs and traces.
- **Admin activity**: what administrators and operators did, to notice a stolen
  administrator session or a compromised server. Its first row counts, over the
  chosen range, administrator rights changed, dashboard requests refused for a
  sign-in or rights the dashboard's own pages never lack, changes refused because
  they targeted an administrator, command-line changes, disabled accounts and
  viewed accounts. Below are their timelines, the dashboard's traffic, actions by
  administrator, and
  the matching log lines and traces. Its counts come from the event and failure
  log lines, which, like all telemetry, are best effort: a request cancelled
  while its commit is in flight can record an event that is never logged (see [telemetry](../architecture/telemetry.md)). The stored history, on
  the dashboard's Events page, is the audit record.

## Look up a failed request

To look up a failed request, paste its trace ID into Explore > Tempo: the
reference that auth's pages and the admin dashboard show below a server error,
which a user's report quotes, the `X-Trace-Id` of an API response, or the trace
ID the admin dashboard shows for an event.

## Sign in to Grafana

Grafana's route is private, and it never signs in through auth: it is needed
most when auth is down (see [recovering auth](../architecture/surfaces.md#recovering-auth)). Sign in as `admin` with the password piqueld
generated:

```sh
piquelctl app exec telemetry grafana -- cat /run/secrets/grafana-admin-password
```

Grafana stores that password on its first start, so regenerating the secret
changes nothing; change it in Grafana instead.

## Connect an application

piquel-fr imports the collector (`[[spec.imports]]` in `infra/piqueld.toml`),
so its staging and production reach it as `collector.telemetry`. Their auth
service sets:

| Variable | Value |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://collector.telemetry:4318`, from the `otlp_endpoint` variable; empty in previews, which keep telemetry on stderr |
| `OTEL_RESOURCE_ATTRIBUTES` | `deployment.environment.name=${{ env.name }}`, so dashboards tell staging and production apart |

Every other `OTEL_*` variable keeps its default; see
[telemetry](../architecture/telemetry.md#configuration). An unreachable collector never blocks a deploy: until the
collector is deployed and linked, export fails, the SDK logs a warning on
stderr, and the services serve normally. A malformed `OTEL_*` variable, by
contrast, stops `serve`, while `migrate` and the administrative commands warn and
log to stderr only.

## Setup

Once, after `infra/telemetry.toml` is on `main`:

```sh
piquelctl --timeout 30m app apply --file infra/telemetry.toml --deploy --yes
piquelctl app repository webhook rotate telemetry   # prints the secret once
piquelctl app repository webhook show telemetry     # prints the payload URL
```

Add that webhook to this repository as for [piquel-fr](deploying.md#setup). `just infra telemetry`
runs the same dashboards locally.
