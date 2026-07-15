#![allow(missing_docs)]

use auth_service::{
    AuthConfig, Es256KeyProvider, FederationApplication, OidcApplication, PasskeyApplication,
    ProductionReadiness, ServiceRpcApplication, health_router, router,
};
use piquel_configuration::{SecretBytes, SecretReference};
use piquel_repository::Database;
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    piquel_telemetry::init("auth_service=info");
    let config = AuthConfig::from_environment()?;
    let readiness_secrets = vec![
        config.key_provider.clone(),
        config.github.client_secret.clone(),
        config.google.client_secret.clone(),
        config.rpc_tls_certificate.clone(),
        config.rpc_tls_private_key.clone(),
        config.rpc_client_ca.clone(),
    ];
    let listener_address: SocketAddr = config.public_listener;
    let database = Database::connect(config.database).await?;
    let key_secret = resolve_secret(config.key_provider.clone()).await?;
    let keys = if config.development_mode {
        Arc::new(Es256KeyProvider::generate_for_development(
            config.signing_key_id.clone(),
        ))
    } else {
        let pem = std::str::from_utf8(key_secret.expose_secret())
            .map_err(|_| anyhow::anyhow!("signing key provider returned invalid data"))?;
        Arc::new(
            Es256KeyProvider::from_pkcs8_pem(config.signing_key_id.clone(), pem).map_err(|()| {
                anyhow::anyhow!("signing key provider returned an invalid ES256 key")
            })?,
        )
    };
    let passkeys = PasskeyApplication::new(
        database.clone(),
        &config.webauthn_rp_id,
        config.public_base_url.as_url(),
        Arc::clone(&keys),
    )?;
    let oidc = if config.development_mode {
        OidcApplication::new_development(
            database.clone(),
            config.public_base_url.as_url(),
            key_secret.expose_secret(),
            keys.clone(),
        )
    } else {
        OidcApplication::new(
            database.clone(),
            config.public_base_url.as_url(),
            key_secret.expose_secret(),
            keys.clone(),
        )
    }
    .map_err(|()| anyhow::anyhow!("invalid OIDC configuration"))?;
    let federation = if config.development_mode {
        FederationApplication::new_development(
            database.clone(),
            config.public_base_url.as_url(),
            config.github,
            config.google,
        )
    } else {
        FederationApplication::new(
            database.clone(),
            config.public_base_url.as_url(),
            config.github,
            config.google,
        )
    }?;
    let rpc = ServiceRpcApplication::new(
        database.clone(),
        config
            .public_base_url
            .as_url()
            .as_str()
            .trim_end_matches('/')
            .to_owned(),
        keys,
    );
    let rpc_certificate = resolve_secret(config.rpc_tls_certificate.clone()).await?;
    let rpc_private_key = resolve_secret(config.rpc_tls_private_key.clone()).await?;
    let rpc_client_ca = resolve_secret(config.rpc_client_ca.clone()).await?;
    let listener = tokio::net::TcpListener::bind(listener_address).await?;
    let health_listener = tokio::net::TcpListener::bind(config.health_listener).await?;
    tracing::info!(%listener_address, "auth service listening");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_sender.send(true);
    });
    tokio::spawn(maintenance_loop(
        database.clone(),
        shutdown_receiver.clone(),
    ));
    let readiness = Arc::new(ProductionReadiness::new(
        database.clone(),
        readiness_secrets,
    ));
    let ingress = (!config.development_mode).then_some(config.trusted_proxy_cidrs.clone());
    let public = axum::serve(
        listener,
        router(Some(passkeys), Some(oidc), Some(federation), ingress)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_receiver.clone()));
    let health = axum::serve(
        health_listener,
        health_router(readiness).into_make_service(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_receiver.clone()));
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            rpc_certificate.expose_secret(),
            rpc_private_key.expose_secret(),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(
            rpc_client_ca.expose_secret(),
        ));
    let private = tonic::transport::Server::builder()
        .tls_config(tls)?
        .timeout(Duration::from_secs(10))
        .concurrency_limit_per_connection(64)
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(5)))
        .add_service(
            rpc.clone()
                .token_server()
                .max_decoding_message_size(16 * 1024),
        )
        .add_service(rpc.auth_server().max_decoding_message_size(1024 * 1024))
        .serve_with_shutdown(
            config.internal_listener,
            wait_for_shutdown(shutdown_receiver.clone()),
        );
    let servers = async {
        tokio::try_join!(
            async { public.await.map_err(anyhow::Error::from) },
            async { health.await.map_err(anyhow::Error::from) },
            async { private.await.map_err(anyhow::Error::from) }
        )
    };
    tokio::pin!(servers);
    tokio::select! {
        result = &mut servers => { result?; }
        () = wait_for_shutdown(shutdown_receiver) => {
            tokio::time::timeout(Duration::from_secs(15), &mut servers)
                .await
                .map_err(|_| anyhow::anyhow!("listener drain exceeded 15 seconds"))??;
        }
    }
    Ok(())
}

async fn resolve_secret(reference: SecretReference) -> anyhow::Result<SecretBytes> {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || reference.resolve()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("secret provider deadline exceeded"))?
    .map_err(|_| anyhow::anyhow!("secret provider task failed"))?
    .map_err(anyhow::Error::from)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c()=>{}, _ = terminate.recv()=>{} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

async fn maintenance_loop(database: Database, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_mins(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => if let Ok(deleted) = database.purge_expired_auth_state(500).await {
                tracing::info!(deleted, "expired authentication state purged");
            } else {
                tracing::warn!("authentication state purge failed");
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}
