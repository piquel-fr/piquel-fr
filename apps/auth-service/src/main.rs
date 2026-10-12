//! Authentication service and its small administrative CLI.
use anyhow::{Context, Result};
use auth_service::AuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use piquel_repository::Database;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, str::FromStr};

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(after_help = "Database commands use AUTH_DATABASE_URL. See README.md for configuration.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(flatten)]
    Database(DatabaseCommand),
    /// Print a random secret for a confidential OIDC client.
    Secret,
}
impl Command {
    async fn run(self) -> Result<()> {
        match self {
            Self::Secret => {
                println!("{}", URL_SAFE_NO_PAD.encode(Self::random_secret()));
                Ok(())
            }
            Self::Database(command) => command.run().await,
        }
    }
    fn random_secret() -> [u8; 32] {
        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        secret
    }
}

/// Commands that connect to `AUTH_DATABASE_URL` first.
#[derive(Subcommand)]
enum DatabaseCommand {
    /// Serve the authentication service.
    Serve,
    /// Apply database migrations.
    Migrate,
    /// Manage signup invitations.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
}
impl DatabaseCommand {
    async fn run(self) -> Result<()> {
        let database = Database::connect(AuthConfig::database_from_environment()?)
            .await
            .context("connect to authentication database")?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => database
                .run_migrations()
                .await
                .context("apply authentication schema"),
            Self::Invite {
                command: InviteCommand::Create { expires_in },
            } => Self::invite(&database, expires_in).await,
        }
    }
    /// Prints a single-use signup link; only the secret's digest is stored.
    async fn invite(database: &Database, expires_in: InviteExpiry) -> Result<()> {
        let secret = Command::random_secret();
        database
            .security()
            .create_invitation(&Sha256::digest(secret), Utc::now() + expires_in.0)
            .await?;
        let mut url = url::Url::parse(
            &env::var("AUTH_PUBLIC_BASE_URL").context("AUTH_PUBLIC_BASE_URL is required")?,
        )?
        .join("register")?;
        url.query_pairs_mut()
            .append_pair("invitation", &URL_SAFE_NO_PAD.encode(secret));
        println!("{url}");
        Ok(())
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
    /// Every five minutes, drains expired auth state in bounded batches until a
    /// pass finds nothing or a one-minute budget runs out. Short pauses between
    /// batches keep cleanup from monopolizing the database under heavy churn.
    async fn purge_expired_state(database: Database) {
        use std::time::Duration;
        let mut interval = tokio::time::interval(Duration::from_mins(5));
        loop {
            interval.tick().await;
            let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
            loop {
                match database.purge_expired_auth_state(1000).await {
                    Ok(0) => break,
                    Ok(_) if tokio::time::Instant::now() >= deadline => {
                        tracing::warn!("expired authentication state cleanup is falling behind");
                        break;
                    }
                    Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                    Err(error) => {
                        tracing::error!(?error, "expired authentication state cleanup failed");
                        break;
                    }
                }
            }
        }
    }
    async fn serve(database: Database) -> Result<()> {
        auth_service::require_embedded_assets()?;
        let config = AuthConfig::from_environment()?;
        let listener = tokio::net::TcpListener::bind(config.public_listener).await?;
        let router = auth_service::router(&config, database.clone()).await?;
        let cleanup = tokio::spawn(Self::purge_expired_state(database));
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(Self::shutdown_signal())
        .await;
        cleanup.abort();
        Ok(result?)
    }
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Print a single-use signup link.
    Create {
        /// How long the link stays valid, in hours or days (e.g. 24h, 7d).
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
    },
}

/// An invitation lifetime of 1 to 365 hours or days.
#[derive(Clone, Copy)]
struct InviteExpiry(Duration);

#[derive(Debug, thiserror::Error)]
#[error("expiry must be 1 to 365 followed by h or d, e.g. 24h or 7d")]
struct InvalidInviteExpiry;

impl FromStr for InviteExpiry {
    type Err = InvalidInviteExpiry;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (number, unit) = value
            .char_indices()
            .last()
            .map(|(index, _)| value.split_at(index))
            .ok_or(InvalidInviteExpiry)?;
        let number = number
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=365).contains(n))
            .ok_or(InvalidInviteExpiry)?;
        match unit {
            "h" => Ok(Self(Duration::hours(number))),
            "d" => Ok(Self(Duration::days(number))),
            _ => Err(InvalidInviteExpiry),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    piquel_telemetry::init("auth_service=info");
    Cli::parse()
        .command
        .unwrap_or(Command::Database(DatabaseCommand::Serve))
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invite_expiry_accepts_bounded_hours_and_days() {
        assert_eq!(
            "24h".parse::<InviteExpiry>().map(|e| e.0).ok(),
            Some(Duration::hours(24))
        );
        assert_eq!(
            "365d".parse::<InviteExpiry>().map(|e| e.0).ok(),
            Some(Duration::days(365))
        );
        for invalid in ["", "d", "0d", "366d", "-1h", "7w", "7 d", "é"] {
            assert!(invalid.parse::<InviteExpiry>().is_err(), "{invalid}");
        }
    }
}
