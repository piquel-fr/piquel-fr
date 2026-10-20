//! Startup configuration, read once from the environment.

use piquel_auth::ClientConfig;
use piquel_common::config::{ConfigurationError, Origin, SecretReference, Variable};
use std::net::SocketAddr;
use url::Url;

/// Auth's issuer, e.g. `https://auth.piquel.fr`.
const AUTH_ORIGIN: Variable = Variable::new("ADMIN_AUTH_ORIGIN");
/// The admin API on auth's private listener, e.g. `http://auth:8081`.
const API_URL: Variable = Variable::new("ADMIN_API_URL");
/// The dashboard's own origin, e.g. `https://admin.piquel.fr`. Sign-in returns to
/// its `/auth/callback`, and sign-out to its root; both are registered for
/// `piquel-admin`.
const ORIGIN: Variable = Variable::new("ADMIN_ORIGIN");
/// Reference to the `piquel-admin` client secret, `file://PATH` or `env://NAME`.
const CLIENT_SECRET: Variable = Variable::new("ADMIN_CLIENT_SECRET");
/// The HTTP listener behind the HTTPS ingress.
const LISTENER: Variable = Variable::new("ADMIN_LISTENER");
/// Where the SDK's login routes are nested: `/auth/login`, `/auth/callback` and
/// `/auth/logout`.
pub const AUTH_MOUNT: &str = "/auth";
/// Listener address when none is configured.
const DEFAULT_LISTENER: &str = "127.0.0.1:3001";

/// The dashboard's validated configuration.
pub struct AdminConfig {
    /// Auth's issuer origin.
    pub issuer: Origin,
    /// The admin API's base URL.
    pub api: Url,
    /// The dashboard's own origin.
    pub origin: Origin,
    /// How the dashboard signs administrators in.
    pub client: ClientConfig,
    /// Where the dashboard listens.
    pub listener: SocketAddr,
}

impl AdminConfig {
    /// Reads and validates every setting, and the client secret.
    ///
    /// # Errors
    /// Names the missing or invalid variable.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        let issuer: Origin = AUTH_ORIGIN.parse()?;
        let origin: Origin = ORIGIN.parse()?;
        let api: Url = API_URL.parse()?;
        if !matches!(api.scheme(), "http" | "https") {
            return Err(
                API_URL.invalid("must be an http:// or https:// URL, e.g. http://auth:8081")
            );
        }
        let secret = CLIENT_SECRET
            .required()?
            .parse::<SecretReference>()
            .and_then(|reference| reference.resolve())
            .map_err(|source| {
                CLIENT_SECRET.error("must resolve through env://NAME or file://PATH", source)
            })?;
        // Sent exactly as auth hashed it from the same reference.
        let secret = secret.utf8()?.to_owned();
        Ok(Self {
            client: ClientConfig {
                client_id: piquel_admin_api::AUDIENCE
                    .parse()
                    .expect("the dashboard's client ID is valid"),
                credentials: piquel_auth::Credentials::Secret(secret.into()),
                redirect_uri: origin.url(&format!("{AUTH_MOUNT}/callback")),
            },
            issuer,
            api,
            origin,
            listener: LISTENER.parse_or(DEFAULT_LISTENER)?,
        })
    }
}
