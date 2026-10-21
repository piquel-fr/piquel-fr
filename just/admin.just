set working-directory := '..'

# Serve the dashboard with the caller's ADMIN_* configuration (see apps/admin-web/README.md).
serve:
    @cargo run --locked -p admin-web
