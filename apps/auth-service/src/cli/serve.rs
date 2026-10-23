//! Serving the public listener and, when configured, the private admin listener.

use super::{CliError, Command};
use crate::{AuthConfig, Jobs};
use axum::Router;
use piquel_repository::Database;
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::watch};

impl Command {
    /// Builds the configured service, starts background jobs and
    /// serves the public listener, and the admin listener when one is configured,
    /// until a shutdown signal. Once in-flight requests drain, running jobs get a
    /// grace period to finish.
    pub(super) async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let public = TcpListener::bind(config.public_listener).await?;
        let admin = match config.admin_listener {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let router = config.router(database.clone())?;
        let admin_router = config.admin_router(database.clone());
        database.observe_connections();
        let jobs = Jobs::start(&database, &config)?;
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let (stop, _) = watch::channel(false);
        let admin = async {
            let Some(listener) = admin else {
                return Ok(());
            };
            tracing::info!(address=%listener.local_addr()?, "admin API listening");
            Self::listen(listener, admin_router, &stop).await
        };
        let signal = async {
            let mut stopped = stop.subscribe();
            tokio::select! {
                () = Self::shutdown_signal() => {
                    stop.send_replace(true);
                }
                _ = stopped.wait_for(|stopped| *stopped) => {}
            }
        };
        let (public, admin, ()) = tokio::join!(Self::listen(public, router, &stop), admin, signal);
        let jobs = jobs.shutdown().await;
        public?;
        admin?;
        Ok(jobs?)
    }

    /// Resolves on Ctrl+C or SIGTERM, the signal container runtimes send on stop.
    async fn shutdown_signal() {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(?error, "Ctrl+C handler unavailable");
                std::future::pending::<()>().await;
            }
        };
        let terminate = async {
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => {
                    terminate.recv().await;
                }
                Err(error) => {
                    tracing::error!(?error, "SIGTERM handler unavailable");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
        tracing::info!("shutting down");
    }

    /// Serves `router` on `listener` until `stop` is set. Once this listener ends,
    /// whatever the reason, it sets `stop`, so the other listener ends too.
    async fn listen(
        listener: TcpListener,
        router: Router,
        stop: &watch::Sender<bool>,
    ) -> std::io::Result<()> {
        let mut stopped = stop.subscribe();
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Fails only once `stop` is dropped, which also means stopping.
            let _ = stopped.wait_for(|stopped| *stopped).await;
        })
        .await;
        stop.send_replace(true);
        result
    }
}
