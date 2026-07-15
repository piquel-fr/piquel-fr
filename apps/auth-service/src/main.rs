#![allow(missing_docs)]

use auth_service::{AuthConfig, Es256KeyProvider, PasskeyApplication, ProductionReadiness, router};
use piquel_repository::Database;
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    piquel_telemetry::init("auth_service=info");
    let config = AuthConfig::from_environment()?;
    let listener_address: SocketAddr = config.public_listener;
    let database = Database::connect(config.database).await?;
    let key_secret = config.key_provider.resolve()?;
    let pem = std::str::from_utf8(key_secret.expose_secret())
        .map_err(|_| anyhow::anyhow!("signing key provider returned invalid data"))?;
    let purpose_keys = Es256KeyProvider::from_pkcs8_pem(config.signing_key_id.clone(), pem)
        .map_err(|()| anyhow::anyhow!("signing key provider returned an invalid ES256 key"))?;
    let passkeys = PasskeyApplication::new(
        database.clone(),
        &config.webauthn_rp_id,
        config.public_base_url.as_url(),
        Arc::new(purpose_keys),
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
