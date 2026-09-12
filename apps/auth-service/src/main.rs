//! Authentication service and its small administrative CLI.
use anyhow::{Context, Result};
use auth_service::AuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_repository::Database;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr};

#[tokio::main]
async fn main() -> Result<()> {
    piquel_telemetry::init("auth_service=info");
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|v| matches!(v.as_str(), "--help" | "-h" | "help"))
    {
        println!(
            "auth-service [serve | migrate | invite create [--expires-in 7d] | secret]\n\nDatabase commands use AUTH_DATABASE_URL. See README.md for configuration."
        );
        return Ok(());
    }
    if args.first().is_some_and(|v| v == "secret") {
        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        println!("{}", URL_SAFE_NO_PAD.encode(secret));
        return Ok(());
    }
    let database = Database::connect(AuthConfig::database_from_environment()?)
        .await
        .context("connect to authentication database")?;
    match args.first().map_or("serve", String::as_str) {
        "migrate" => database
            .run_migrations()
            .await
            .context("apply authentication schema")?,
        "invite" => {
            anyhow::ensure!(
                args.get(1).is_some_and(|v| v == "create"),
                "Usage: auth-service invite create [--expires-in 7d]"
            );
            let duration = match &args[2..] {
                [] => Duration::days(7),
                [flag, value] if flag == "--expires-in" => {
                    let (number, unit) = value.split_at(
                        value
                            .len()
                            .checked_sub(1)
                            .filter(|n| value.is_char_boundary(*n))
                            .context("invalid expiry")?,
                    );
                    let number: i64 = number.parse().context("expiry must be e.g. 7d or 24h")?;
                    anyhow::ensure!(
                        number > 0 && number <= 365,
                        "expiry must be between 1 and 365 units"
                    );
                    match unit {
                        "d" => Duration::days(number),
                        "h" => Duration::hours(number),
                        _ => anyhow::bail!("expiry must end in d or h"),
                    }
                }
                _ => anyhow::bail!("Usage: auth-service invite create [--expires-in 7d]"),
            };
            let mut secret = [0; 32];
            OsRng.fill_bytes(&mut secret);
            database
                .security()
                .create_invitation(&Sha256::digest(secret), Utc::now() + duration)
                .await?;
            let mut url = url::Url::parse(
                &env::var("AUTH_PUBLIC_BASE_URL").context("AUTH_PUBLIC_BASE_URL is required")?,
            )?
            .join("register")?;
            url.query_pairs_mut()
                .append_pair("invitation", &URL_SAFE_NO_PAD.encode(secret));
            println!("{url}");
        }
        "serve" => {
            auth_service::require_embedded_assets()?;
            let config = AuthConfig::from_environment()?;
            let listener = tokio::net::TcpListener::bind(config.public_listener).await?;
            let router = auth_service::router(&config, database.clone()).await?;
            let cleanup = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    if let Err(error) = database.purge_expired_auth_state(1000).await {
                        tracing::error!(?error, "expired authentication state cleanup failed");
                    }
                }
            });
            tracing::info!(address=%config.public_listener,"authentication service listening");
            let result = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    tracing::error!(?error, "shutdown signal unavailable");
                }
            })
            .await;
            cleanup.abort();
            result?;
        }
        _ => anyhow::bail!("Unknown command. Run auth-service --help"),
    }
    Ok(())
}
