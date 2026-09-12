//! One authentication authority: browser flows, settings API, and OIDC.
mod assets;
mod email;
mod federation;
mod oidc;
mod passkey;
mod security;

use federation::{FederationApplication, ProviderConfiguration};
use oidc::{OidcApplication, Rs256KeyProvider};
use passkey::PasskeyApplication;

use anyhow::{Context, Result};
use axum::{Json, Router, extract::DefaultBodyLimit, middleware, routing::get};
use piquel_configuration::{PublicUrl, SecretReference};
use piquel_repository::{BootstrapOidcClient, Database, DatabaseConfig};
use serde::Deserialize;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use url::Url;

/// Runtime configuration; secret values are never logged.
pub struct AuthConfig {
    public_base_url: Url,
    settings_url: Url,
    /// Address bound by the single public HTTP listener.
    pub public_listener: SocketAddr,
    key_provider: Option<SecretReference>,
    signing_key_id: String,
    development: bool,
    invite_required: bool,
    github: Option<ProviderConfiguration>,
    google: Option<ProviderConfiguration>,
    clients: Vec<BootstrapOidcClient>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    id: String,
    display_name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_uris: Vec<String>,
    #[serde(default = "ClientConfig::scopes")]
    allowed_scopes: Vec<String>,
    #[serde(default)]
    allow_refresh: bool,
    #[serde(default)]
    trusted: bool,
    #[serde(default = "ClientConfig::enabled")]
    enabled: bool,
    client_secret: Option<String>,
}
impl ClientConfig {
    fn scopes() -> Vec<String> {
        vec!["openid".into(), "profile".into(), "email".into()]
    }
    fn enabled() -> bool {
        true
    }
    fn into_client(self) -> Result<BootstrapOidcClient> {
        let secret = self
            .client_secret
            .map(|reference| -> Result<Vec<u8>> {
                let secret = SecretReference::parse(&reference)?.resolve()?;
                OidcApplication::client_secret_hash(std::str::from_utf8(secret.expose_secret())?)
            })
            .transpose()?;
        Ok(BootstrapOidcClient {
            allowed_audiences: vec![self.id.clone()],
            id: self.id,
            display_name: self.display_name,
            redirect_uris: self.redirect_uris,
            post_logout_uris: self.post_logout_uris,
            allowed_scopes: self.allowed_scopes,
            allow_refresh: self.allow_refresh,
            trusted: self.trusted,
            enabled: self.enabled,
            client_secret_hash: secret,
        })
    }
}
impl AuthConfig {
    fn required(name: &'static str) -> Result<String> {
        env::var(name).with_context(|| format!("{name} is required"))
    }
    fn flag(name: &str, default: bool) -> Result<bool> {
        match env::var(name).as_deref() {
            Ok("true") => Ok(true),
            Ok("false") => Ok(false),
            Err(env::VarError::NotPresent) => Ok(default),
            _ => anyhow::bail!("{name} must be true or false"),
        }
    }
    fn provider(name: &str) -> Result<Option<ProviderConfiguration>> {
        let id = env::var(format!("AUTH_{name}_CLIENT_ID")).ok();
        let secret = env::var(format!("AUTH_{name}_CLIENT_SECRET")).ok();
        match (id, secret) {
            (None, None) => Ok(None),
            (Some(client_id), Some(secret)) => Ok(Some(ProviderConfiguration {
                client_id,
                client_secret: SecretReference::parse(&secret)?,
            })),
            _ => {
                anyhow::bail!("Configure both AUTH_{name}_CLIENT_ID and AUTH_{name}_CLIENT_SECRET")
            }
        }
    }
    /// Loads database settings independently for migration/invitation commands.
    ///
    /// # Errors
    /// Returns missing configuration or invalid database/TLS settings.
    pub fn database_from_environment() -> Result<DatabaseConfig> {
        let url = Self::required("AUTH_DATABASE_URL")?;
        Ok(if Self::flag("AUTH_DEVELOPMENT_MODE", false)? {
            DatabaseConfig::new_development(&url, 10, Duration::from_secs(5))?
        } else {
            DatabaseConfig::new(&url, 10, Duration::from_secs(5))?
        })
    }
    /// Validates service, provider, and client settings before startup.
    ///
    /// # Errors
    /// Returns invalid settings, unreadable client configuration, or unresolved secrets.
    pub fn from_environment() -> Result<Self> {
        let development = Self::flag("AUTH_DEVELOPMENT_MODE", false)?;
        let parse = |value: &str| -> Result<Url> {
            Ok(if development {
                PublicUrl::parse_development(value)?
            } else {
                PublicUrl::parse(value)?
            }
            .as_url()
            .clone())
        };
        let public_base_url = parse(&Self::required("AUTH_PUBLIC_BASE_URL")?)?;
        anyhow::ensure!(
            public_base_url.path() == "/"
                && public_base_url.username().is_empty()
                && public_base_url.password().is_none(),
            "AUTH_PUBLIC_BASE_URL must be an origin"
        );
        let settings_url = parse(
            &env::var("AUTH_SETTINGS_URL").unwrap_or_else(|_| "https://piquel.fr/settings".into()),
        )?;
        anyhow::ensure!(
            settings_url.username().is_empty() && settings_url.password().is_none(),
            "AUTH_SETTINGS_URL must not contain credentials"
        );
        let clients = env::var("AUTH_CLIENTS_FILE")
            .ok()
            .map(|path| -> Result<Vec<BootstrapOidcClient>> {
                let inputs: Vec<ClientConfig> =
                    serde_json::from_slice(&std::fs::read(path).context("read OIDC clients file")?)
                        .context("parse OIDC clients file")?;
                inputs.into_iter().map(ClientConfig::into_client).collect()
            })
            .transpose()?
            .unwrap_or_default();
        let unique: std::collections::HashSet<_> =
            clients.iter().map(|client| &client.id).collect();
        anyhow::ensure!(
            unique.len() == clients.len(),
            "AUTH_CLIENTS_FILE contains duplicate client IDs"
        );
        let key_provider = env::var("AUTH_KEY_PROVIDER")
            .ok()
            .map(|v| SecretReference::parse(&v))
            .transpose()?;
        anyhow::ensure!(
            development || key_provider.is_some(),
            "AUTH_KEY_PROVIDER is required outside development"
        );
        Ok(Self {
            public_base_url,
            settings_url,
            public_listener: env::var("AUTH_PUBLIC_LISTENER")
                .unwrap_or_else(|_| "127.0.0.1:8080".into())
                .parse()?,
            key_provider,
            signing_key_id: env::var("AUTH_SIGNING_KEY_ID").unwrap_or_else(|_| "primary".into()),
            development,
            invite_required: Self::flag("AUTH_INVITE_REQUIRED", true)?,
            github: Self::provider("GITHUB")?,
            google: Self::provider("GOOGLE")?,
            clients,
        })
    }
    fn oidc(&self, database: &Database) -> Result<OidcApplication> {
        let (keys, refresh_secret) = if let Some(reference) = &self.key_provider {
            let secret = reference.resolve()?;
            let pem = std::str::from_utf8(secret.expose_secret())
                .context("signing key is not UTF-8 PEM")?;
            (
                Rs256KeyProvider::from_pem(&self.signing_key_id, pem)?,
                secret.expose_secret().to_vec(),
            )
        } else {
            (
                Rs256KeyProvider::generate_for_development(&self.signing_key_id)?,
                security::BrowserSecret::new().encoded().into_bytes(),
            )
        };
        let keys = Arc::new(keys);
        let oidc = if self.development {
            OidcApplication::new_development(
                database.clone(),
                &self.public_base_url,
                &refresh_secret,
                keys,
            )
        } else {
            OidcApplication::new(
                database.clone(),
                &self.public_base_url,
                &refresh_secret,
                keys,
            )
        }
        .map_err(|()| anyhow::anyhow!("invalid OIDC configuration"))?;

        Ok(oidc)
    }
}

/// Builds the service with browser-origin protection around every public endpoint.
///
/// # Errors
/// Returns signing, provider, or database errors before accepting requests.
pub async fn router(config: &AuthConfig, database: Database) -> Result<Router> {
    let oidc = config.oidc(&database)?;
    let passkeys = PasskeyApplication::new(
        database.clone(),
        config
            .public_base_url
            .host_str()
            .context("auth host missing")?,
        &config.public_base_url,
        config.invite_required,
    )?;
    let federation = FederationApplication::new(
        database.clone(),
        &config.public_base_url,
        config.github.clone(),
        config.google.clone(),
    )?
    .with_settings_url(&config.settings_url)?;
    let mut tx = database.begin().await?;
    tx.oidc().disable_all_clients().await?;
    for client in &config.clients {
        tx.oidc().bootstrap_client(client).await?;
    }
    tx.commit().await?;
    let provider_names = [
        ("github", config.github.is_some()),
        ("google", config.google.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<Vec<_>>();
    let public_config = serde_json::json!({"settings_url":config.settings_url,"providers":provider_names,"invite_required":config.invite_required});
    let health = database.clone();
    let policy = security::HttpSecurity {
        database,
        auth_origin: config.public_base_url.origin().ascii_serialization(),
        settings_origin: config.settings_url.origin().ascii_serialization(),
        client_origins: Arc::new(
            config
                .clients
                .iter()
                .filter(|c| c.client_secret_hash.is_none())
                .flat_map(|c| &c.redirect_uris)
                .filter_map(|uri| {
                    Url::parse(uri)
                        .ok()
                        .map(|url| url.origin().ascii_serialization())
                })
                .collect(),
        ),
    };
    Ok(Router::new()
        .route(
            "/health/live",
            get(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/health/ready",
            get(move || {
                let db = health.clone();
                async move {
                    db.health_check()
                        .await
                        .map(|()| axum::http::StatusCode::NO_CONTENT)
                        .map_err(security::ApiError::from)
                }
            }),
        )
        .route(
            "/config",
            get(move || {
                let value = public_config.clone();
                async { Json(value) }
            }),
        )
        .merge(passkeys.routes())
        .merge(oidc::routes(oidc))
        .merge(federation::routes(federation))
        .fallback(assets::serve)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(
            policy,
            security::HttpSecurity::protect,
        )))
}

/// Fails explicitly if frontend assets have not been built into this executable.
///
/// # Errors
/// Returns an actionable build error when embedded assets are missing.
pub fn require_embedded_assets() -> Result<()> {
    anyhow::ensure!(
        !assets::FILES.is_empty(),
        "Build the auth frontend with pnpm --filter @piquel/auth-web build before compiling auth-service"
    );
    Ok(())
}
