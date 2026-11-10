set working-directory := '..'

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy sourceorigin --local {{ args }}
    piquelctl --timeout 10m preview wait sourceorigin "$(git branch --show-current)" {{ args }} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl --timeout 5m preview delete sourceorigin "$(git branch --show-current)" {{ args }} --yes

# Each telemetry config is checked by the image infra/telemetry.toml runs it
# with, so by the version that will read it. Needs piquelctl and Docker.
# Validate the piqueld manifests and the telemetry configs.
check:
    #!/usr/bin/env bash
    set -euo pipefail
    piquelctl app validate --file infra/piqueld.toml
    piquelctl app validate --file infra/telemetry.toml
    image() { grep -o "image = \"$1:[^\"]*\"" infra/telemetry.toml | cut -d '"' -f 2; }
    run() { docker run --rm --volume "$PWD/infra/telemetry:/etc/telemetry:ro" "$@"; }
    run "$(image otel/opentelemetry-collector-contrib)" validate --config=/etc/telemetry/collector.yaml
    run --entrypoint promtool "$(image prom/prometheus)" check config /etc/telemetry/prometheus.yaml
    run "$(image grafana/loki)" -config.file=/etc/telemetry/loki.yaml -verify-config
    run "$(image grafana/tempo)" -config.file=/etc/telemetry/tempo.yaml -config.verify=true

# Point auth at it with OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 and
# OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=local.
# Grafana's all-in-one OpenTelemetry backend, with the SourceOrigin dashboards, at http://localhost:3000.
telemetry:
    docker run --rm --name sourceorigin-telemetry \
        -p 127.0.0.1:3000:3000 -p 127.0.0.1:4318:4318 \
        -v "$PWD/infra/telemetry/grafana/dashboards.yaml:/otel-lgtm/grafana/conf/provisioning/dashboards/sourceorigin.yaml:ro" \
        -v "$PWD/infra/telemetry/grafana/dashboards:/etc/grafana/dashboards:ro" \
        grafana/otel-lgtm:0.37.0
