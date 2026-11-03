//! Serving the public listener and, when configured, the admin dashboard's and
//! the site's listeners.

use super::{CliError, Command};
use crate::{AuthConfig, Jobs, KeyStore};
use axum::Router;
use piquel_repository::Database;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

impl Command {
    /// Builds the configured service, loads its signing keys, starts background
    /// jobs and serves the public listener, and the admin dashboard's and the
    /// site's listeners when they are configured, until a shutdown signal. Once
    /// in-flight requests drain, running jobs get a grace period to finish.
    pub(super) async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let public = TcpListener::bind(config.public_listener).await?;
        let admin = match &config.dashboard {
            Some(dashboard) => Some((TcpListener::bind(dashboard.listener).await?, dashboard)),
            None => None,
        };
        let site = match config.site_listener {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let store = KeyStore::new(database.clone(), Arc::clone(&config.key_encryption_key));
        let keys = store.start().await?;
        let public = Some((
            "authentication service",
            public,
            config.router(database.clone(), &keys)?,
        ));
        let admin = match admin {
            Some((listener, dashboard)) => Some((
                "admin dashboard",
                listener,
                config.admin_router(database.clone(), dashboard)?,
            )),
            None => None,
        };
        let site = site.map(|listener| ("site", listener, config.site_router(database.clone())));
        database.observe_connections();
        let jobs = Jobs::start(&database, &config, &store, &keys)?;
        let (stop, _) = watch::channel(false);
        let signal = async {
            let mut stopped = stop.subscribe();
            tokio::select! {
                () = Self::shutdown_signal() => {
                    stop.send_replace(true);
                }
                _ = stopped.wait_for(|stopped| *stopped) => {}
            }
        };
        let (public, admin, site, ()) = tokio::join!(
            Self::listen(public, &stop),
            Self::listen(admin, &stop),
            Self::listen(site, &stop),
            signal,
        );
        let jobs = jobs.shutdown().await;
        public?;
        admin?;
        site?;
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

    /// Serves the `served` listener's router, if it is configured, until `stop`
    /// is set, logging its name and address. Once this listener ends, whatever
    /// the reason, it sets `stop`, so the other listeners end too.
    async fn listen(
        served: Option<(&str, TcpListener, Router)>,
        stop: &watch::Sender<bool>,
    ) -> std::io::Result<()> {
        let Some((name, listener, router)) = served else {
            return Ok(());
        };
        tracing::info!(address=%listener.local_addr()?, "{name} listening");
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
