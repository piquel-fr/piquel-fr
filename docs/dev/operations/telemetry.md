# Telemetry stack

This page helps you watch staging and production: sign in to Grafana, look up a
failed request by its trace ID, and follow what administrators do.

`infra/telemetry.toml` is the `sourceorigin-observability` application. Its one environment,
`production`, follows `main`, and serves both of sourceorigin's environments, which
dashboards tell apart. Grafana, at `grafana.sourceorigin.dev`, is reachable from the
tailnet only, and never signs in through auth: it is needed most when auth is
down.

## Sign in to Grafana

1. Print the `admin` password piqueld generated:

   ```sh
   piquelctl app exec sourceorigin-observability grafana -- cat /run/secrets/grafana-admin-password
   ```

2. From a device on the tailnet, open `https://grafana.sourceorigin.dev`, and sign in
   as `admin` with that password.
3. Open **Dashboards**, then the **SourceOrigin** folder, and choose the
   environment at the top of a dashboard.

Grafana stores that password on its first start, so regenerating the secret
changes nothing: change the password in Grafana instead.

## Look up a failed request

A trace ID names one request. You find it:

- below a server error on auth's pages and the admin dashboard, as the
  reference a user's report quotes;
- in the `X-Trace-Id` header of an API response;
- next to an event, on the admin dashboard's **Events** page.

To look it up:

1. In Grafana, open **Explore**, and choose the **Tempo** data source.
2. Paste the trace ID as the query, and run it.
3. Read the trace's spans, then open its log lines from the trace, which link
   to **Loki**.

A log line in **Loki** links back to its trace the same way. Traces are kept 14
days, and logs 30.

## Watch administrator activity

The **Admin activity** dashboard shows what administrators and operators did,
to notice a stolen administrator session or a compromised server:

1. Open **Admin activity**, and choose the environment and the time range.
2. Read its first row, **At a glance**: **Administrator changes**, **Refused
   sign-ins**, the dashboard requests refused for a sign-in or rights its own
   pages never lack, **Refused on administrators**, the changes refused because
   they targeted an administrator, **Operator actions**, the command line's
   changes, **Accounts disabled** and **Accounts viewed**. Work you know of
   should explain each.
3. For anything that isn't, read **Actions by administrator** and
   **Administrative events** below, and open their traces.

Its counts come from log lines, which, like all telemetry, are best effort: a
request cancelled while its commit is in flight can record an event that is
never logged (see [telemetry](../architecture/telemetry.md)). The stored
history, on the admin dashboard's **Events** page or through
`auth-service audit list`, is the audit record. If something looks wrong, see
[a stolen administrator session](incidents.md#a-stolen-administrator-session-or-a-compromised-administrator-account).

## Set up the stack

Once, after `infra/telemetry.toml` is on `main`:

1. Save the manifest and deploy it:

   ```sh
   piquelctl --timeout 30m app apply --file infra/telemetry.toml --deploy --yes
   ```

2. Create its webhook's secret, and print its payload URL:

   ```sh
   piquelctl app repository webhook rotate sourceorigin-observability   # prints the secret once
   piquelctl app repository webhook show sourceorigin-observability     # prints the payload URL
   ```

3. Add that webhook to this repository, as for
   [sourceorigin](deploying.md#set-up-the-environments).

An unreachable collector never blocks a deployment of sourceorigin. Until the
collector is deployed and linked, export fails, the services log a warning on
stderr, and serve normally. A malformed endpoint, timeout or
`OTEL_SDK_DISABLED`, by contrast, stops `serve` and the web app, while `migrate` and the
administrative commands warn and log to stderr only.

## Run the dashboards locally

```sh
just infra telemetry
```

This runs Grafana's all-in-one OpenTelemetry backend, with both dashboards, at
`http://localhost:3000`. Point a local auth at it: see
[telemetry](../architecture/telemetry.md#locally).

## Services

| Service | Image | Role |
| --- | --- | --- |
| `collector` | `otel/opentelemetry-collector-contrib` | OTLP/HTTP on port 4318, with a memory limit and batching. It deletes paths, query strings, request headers and client addresses that reach it anyway |
| `prometheus` | `prom/prometheus` | Metrics, received over OTLP, kept 30 days |
| `tempo` | `grafana/tempo` | Traces, kept 14 days |
| `loki` | `grafana/loki` | Logs, received over OTLP, kept 30 days |
| `grafana` | `grafana/grafana` | Dashboards at `grafana.sourceorigin.dev` |

Their configuration is in `infra/telemetry/`, mounted as piqueld files.

## Dashboards

Grafana provisions the three data sources, linked so a log line opens its trace
and a trace its logs, and two dashboards in the **SourceOrigin** folder:

- **Auth overview**: traffic, errors and latency by route, sign-ins,
  registrations, tokens, refresh revocations, throttling, events by kind, the
  database pool, cleanup, the delivery queue, logs and traces. Its
  **Deliveries** row charts pending deliveries, the oldest one's age and
  attempts by outcome, per channel (see
  [the delivery queue](../architecture/delivery-queue.md#metrics)).
- **Admin activity**: what administrators and operators did, as
  [watch administrator activity](#watch-administrator-activity) describes.

## How applications connect

sourceorigin imports the collector (`[[spec.imports]]` in `infra/piqueld.toml`),
so its staging and production reach it as `collector.sourceorigin-observability`. Their `auth`
and `web` services set:

| Variable | Value |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://collector.sourceorigin-observability:4318`, from the `otlp_endpoint` variable; empty in previews, which keep telemetry on stderr |
| `OTEL_RESOURCE_ATTRIBUTES` | `deployment.environment.name=${{ env.name }}`, so dashboards tell staging and production apart |

Every other `OTEL_*` variable keeps its default: see
[telemetry](../architecture/telemetry.md#configuration).
