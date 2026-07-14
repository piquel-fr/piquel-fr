#![allow(missing_docs)]

use auth_service::{AuthConfig, PasskeyApplication, ProductionReadiness, router};
use piquel_repository::Database;
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    piquel_telemetry::init("auth_service=info");
    let config = AuthConfig::from_environment()?;
    let listener_address: SocketAddr = config.public_listener;
    let database = Database::connect(config.database).await?;
    let passkeys = PasskeyApplication::new(
        database.clone(),
        &config.webauthn_rp_id,
        config.public_base_url.as_url(),
    )?;
    let listener = tokio::net::TcpListener::bind(listener_address).await?;
    tracing::info!(%listener_address, "auth service listening");
    axum::serve(
        listener,
        router(
            Arc::new(ProductionReadiness::new(database, config.key_provider)),
            Some(passkeys),
        ),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
