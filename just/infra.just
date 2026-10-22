set working-directory := '..'

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy piquel-fr --local {{ args }}
    piquelctl --timeout 10m preview wait piquel-fr "$(git branch --show-current)" {{ args }} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl preview delete piquel-fr "$(git branch --show-current)" {{ args }} --yes

# Point auth at it with OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 and
# OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=local.
# Grafana's all-in-one OpenTelemetry backend, with the Auth overview dashboard, at http://localhost:3000.
telemetry:
    docker run --rm --name piquel-telemetry \
        -p 127.0.0.1:3000:3000 -p 127.0.0.1:4318:4318 \
        -v "$PWD/infra/telemetry/grafana/dashboards.yaml:/otel-lgtm/grafana/conf/provisioning/dashboards/piquel.yaml:ro" \
        -v "$PWD/infra/telemetry/grafana/dashboards:/etc/grafana/dashboards:ro" \
        grafana/otel-lgtm:0.37.0
