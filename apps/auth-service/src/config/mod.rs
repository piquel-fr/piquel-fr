//! Validated startup configuration, grouped by application.

/// The database connections, at runtime and as the schema owner.
mod database;
/// Email to account holders and its SMTP relay.
mod email;
/// External identity providers' credentials.
mod federation;
/// Token digest keys, the link keys derived from them, and the audit key.
mod keys;

pub(crate) use email::EmailConfig;
pub(crate) use federation::{FederationConfig, ProviderConfig};
use keys::KEY_ENCRYPTION_KEY;
pub(crate) use keys::LinkKeys;
#[cfg(test)]
pub(crate) use keys::TokenDigestKey;
pub use keys::{AuditConfig, TokenDigestKeys};

use crate::recovery::RecoveryLinks;
use email::SMTP_URL;
use ipnet::IpNet;
use piquel_common::config::{ConfigurationError, Origin, SecretReference, Variable};
use piquel_crypto::KeyEncryptionKey;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use url::Url;

/// [`PUBLIC_LISTENER`] when none is configured; the HTTPS ingress proxies to it.
const DEFAULT_PUBLIC_LISTENER: &str = "127.0.0.1:8080";
/// [`WEB_ORIGIN`] when none is configured: production's.
const DEFAULT_WEB_ORIGIN: &str = "https://piquel.fr";
/// [`REQUESTS_PER_MINUTE`] when none is configured: enough for a person, not
/// for a browser suite or a scraper.
const DEFAULT_REQUESTS_PER_MINUTE: &str = "120";

piquel_common::variables! {
    /// The service's own variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    /// The exact origin auth serves, such as `https://auth.piquel.fr`. It is the
    /// OpenID Connect issuer and the passkeys' relying party, so it must use a
    /// domain name. Required.
    pub const PUBLIC_BASE_URL = "AUTH_PUBLIC_BASE_URL";
    /// The address auth listens on, behind the HTTPS ingress.
    const PUBLIC_LISTENER = "AUTH_PUBLIC_LISTENER", default DEFAULT_PUBLIC_LISTENER;
    /// piquel.fr's origin. Every page links its privacy policy and terms, and
    /// discovery advertises them.
    const WEB_ORIGIN = "AUTH_WEB_ORIGIN", default DEFAULT_WEB_ORIGIN;
    /// The address the admin dashboard listens on, such as `0.0.0.0:8081`. Set it
    /// together with `AUTH_ADMIN_ORIGIN`; without them, auth serves no dashboard.
    /// Only a private route may reach this listener.
    const ADMIN_LISTENER = "AUTH_ADMIN_LISTENER";
    /// The admin dashboard's origin, such as `https://admin.piquel.fr`. Set it
    /// together with `AUTH_ADMIN_LISTENER`.
    const ADMIN_ORIGIN = "AUTH_ADMIN_ORIGIN";
    /// `false` lets anyone sign up; `true`, the default, requires an invitation.
    /// It changes signing up only: existing accounts keep their access.
    const INVITE_REQUIRED = "AUTH_INVITE_REQUIRED";
    /// How many requests one client may make a minute in each rate category, such
    /// as pages, sign-in and tokens.
    const REQUESTS_PER_MINUTE = "AUTH_REQUESTS_PER_MINUTE", default DEFAULT_REQUESTS_PER_MINUTE;
    /// The proxies in front of auth, as comma-separated IP addresses or CIDR
    /// ranges. Each must overwrite `X-Forwarded-For` with the one client address,
    /// which auth then throttles on. A missing or ambiguous header from one of them
    /// is refused, and the header is ignored from any other peer. Unset, auth
    /// trusts `PIQUELD_INGRESS_PROXIES`, and without either it throttles on the
    /// direct peer's address.
    const TRUSTED_PROXIES = "AUTH_TRUSTED_PROXIES";
    /// The gateway ranges piqueld gives every service, trusted when
    /// `AUTH_TRUSTED_PROXIES` is unset.
    const INGRESS_PROXIES = "PIQUELD_INGRESS_PROXIES";
}

/// The removed PEM signing key and its ID. Startup refuses them, so a deployment
/// that still sets them learns that signing keys now live in the database.
const REMOVED_KEY_VARIABLES: [Variable; 2] = [
    Variable::new("AUTH_KEY_PROVIDER"),
    Variable::new("AUTH_SIGNING_KEY_ID"),
];
/// The removed OIDC clients file. Startup refuses it, so a deployment that still
/// sets it fails loudly instead of silently serving without its clients.
const CLIENTS_FILE: Variable = Variable::new("AUTH_CLIENTS_FILE");

/// Passkey relying-party configuration.
#[derive(Clone)]
pub(crate) struct PasskeyConfig {
    /// Exact validated relying-party origin.
    pub origin: Origin,
    /// Registration admission policy.
    pub invite_required: bool,
}
impl PasskeyConfig {
    /// Reads the passkey policy and validates that the origin has a domain RP ID.
    pub(crate) fn from_environment(origin: &Origin) -> Result<Self, ConfigurationError> {
        if !matches!(origin.as_url().host(), Some(url::Host::Domain(_))) {
            return Err(PUBLIC_BASE_URL
                .invalid("must use a domain name for WebAuthn, e.g. https://auth.piquel.fr"));
        }
        Ok(Self {
            origin: origin.clone(),
            invite_required: INVITE_REQUIRED.flag(true)?,
        })
    }
}

/// The exact OIDC issuer and the keys of its opaque tokens. Signing keys live in
/// the database (see `crate::keys`).
#[derive(Clone)]
pub(crate) struct OidcConfig {
    /// Exact HTTPS issuer origin.
    pub origin: Origin,
    /// Keys under which opaque token secrets are stored.
    pub digest_keys: Arc<TokenDigestKeys>,
    /// Piquel's policies, which discovery advertises.
    pub policies: PolicyLinks,
}

/// Piquel's policies, at their paths on piquel.fr: every page's footer links them,
/// and discovery advertises them as `op_policy_uri` and `op_tos_uri`.
#[derive(Clone)]
pub(crate) struct PolicyLinks {
    /// The privacy policy.
    pub privacy: Url,
    /// The terms of service.
    pub terms: Url,
}

impl PolicyLinks {
    /// The policies piquel.fr serves at `web`.
    pub(crate) fn on(web: &Origin) -> Self {
        let paths = piquel_ui::Policies::PATHS;
        Self {
            privacy: web.url(paths.privacy),
            terms: web.url(paths.terms),
        }
    }

    /// The policies, as a page's footer links them.
    pub(crate) fn links(&self) -> piquel_ui::Policies<'_> {
        piquel_ui::Policies {
            privacy: self.privacy.as_str(),
            terms: self.terms.as_str(),
        }
    }
}

/// The admin dashboard, which auth serves on a listener of its own, for its own
/// origin.
#[derive(Clone)]
pub struct DashboardConfig {
    /// Address bound by the admin listener, which only a private route may reach.
    pub listener: SocketAddr,
    /// The dashboard's origin, which auth's handoff page sends administrators to.
    pub origin: Origin,
}

impl DashboardConfig {
    /// Reads the admin listener and the dashboard's origin, which are set together,
    /// or neither, when auth serves no dashboard.
    fn from_environment() -> Result<Option<Self>, ConfigurationError> {
        match (ADMIN_LISTENER.optional()?, ADMIN_ORIGIN.optional()?) {
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Ok(Some(Self {
                listener: ADMIN_LISTENER.parse()?,
                origin: ADMIN_ORIGIN.parse()?,
            })),
            (Some(_), None) => Err(ADMIN_ORIGIN.invalid(
                "must be set with AUTH_ADMIN_LISTENER: the dashboard's origin, e.g. https://admin.piquel.fr",
            )),
            (None, Some(_)) => Err(ADMIN_LISTENER.invalid(
                "must be set with AUTH_ADMIN_ORIGIN: the address the dashboard listens on",
            )),
        }
    }
}

/// Validated service configuration combining one section per application.
pub struct AuthConfig {
    /// Address bound by the HTTP listener behind piqueld.
    pub public_listener: SocketAddr,
    /// The admin dashboard, if auth serves it.
    pub dashboard: Option<DashboardConfig>,
    /// Passkey policy and origin.
    pub(crate) passkey: PasskeyConfig,
    /// External identity provider policy.
    pub(crate) federation: FederationConfig,
    /// OIDC issuer and token digest keys.
    pub(crate) oidc: OidcConfig,
    /// Email to account holders.
    pub(crate) email: EmailConfig,
    /// Seals and opens the signing keys in the database.
    pub key_encryption_key: Arc<KeyEncryptionKey>,
    /// The audit checkpoint key.
    pub(crate) audit: AuditConfig,
    /// Trusted reverse-proxy peers.
    pub(crate) trusted_proxies: Vec<IpNet>,
    /// How many requests a client may make a minute, in each rate category.
    pub(crate) requests_per_minute: i32,
}

impl AuthConfig {
    /// Validates all service and application settings before startup. The removed
    /// clients file is refused first: clients now live in the database.
    ///
    /// # Errors
    /// Names invalid or missing variables and retains safe underlying sources.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        if CLIENTS_FILE.optional()?.is_some() {
            return Err(CLIENTS_FILE.invalid(
                "was removed; clients live in the database. See `auth-service client --help`.",
            ));
        }
        for variable in REMOVED_KEY_VARIABLES {
            if variable.optional()?.is_some() {
                return Err(variable.invalid(
                    "was removed; signing keys live in the database. See `auth-service keys --help`.",
                ));
            }
        }
        let origin: Origin = PUBLIC_BASE_URL.parse()?;
        let digest_keys = Arc::new(TokenDigestKeys::from_environment()?);
        Ok(Self {
            public_listener: PUBLIC_LISTENER.parse_or(DEFAULT_PUBLIC_LISTENER)?,
            dashboard: DashboardConfig::from_environment()?,
            passkey: PasskeyConfig::from_environment(&origin)?,
            federation: FederationConfig::from_environment(&origin)?,
            email: EmailConfig::from_environment(&origin, &digest_keys)?,
            audit: AuditConfig::from_environment(&origin)?,
            oidc: OidcConfig {
                origin,
                digest_keys,
                policies: PolicyLinks::on(&WEB_ORIGIN.parse_or(DEFAULT_WEB_ORIGIN)?),
            },
            key_encryption_key: Arc::new(Self::key_encryption_key_from_environment()?),
            trusted_proxies: Self::trusted_proxies()?,
            requests_per_minute: Self::requests_per_minute()?,
        })
    }

    /// `AUTH_REQUESTS_PER_MINUTE`, a positive count the counters can hold.
    fn requests_per_minute() -> Result<i32, ConfigurationError> {
        let budget: std::num::NonZeroU32 =
            REQUESTS_PER_MINUTE.parse_or(DEFAULT_REQUESTS_PER_MINUTE)?;
        i32::try_from(budget.get())
            .map_err(|source| REQUESTS_PER_MINUTE.error("is too large", source))
    }

    /// Loads what the `user recover` command needs to print a recovery link: the
    /// public origin and the current token digest key, which every other setting
    /// can do without.
    ///
    /// # Errors
    /// Names an invalid or missing origin or key.
    pub(crate) fn recovery_links_from_environment() -> Result<RecoveryLinks, ConfigurationError> {
        let origin: Origin = PUBLIC_BASE_URL.parse()?;
        Ok(TokenDigestKeys::from_environment()?.recovery_links(&origin))
    }

    /// Reads whether email is enabled (`AUTH_SMTP_URL` is set), for commands that
    /// send no email themselves.
    ///
    /// # Errors
    /// Names an unreadable variable.
    pub(crate) fn mails_from_environment() -> Result<bool, ConfigurationError> {
        Ok(SMTP_URL.optional()?.is_some())
    }

    /// Reads the key-encryption key, for serving and for the `keys` commands.
    ///
    /// # Errors
    /// Names a missing or unreadable reference, or a value that is not 32 bytes
    /// in unpadded base64url.
    pub fn key_encryption_key_from_environment() -> Result<KeyEncryptionKey, ConfigurationError> {
        let reference: SecretReference = KEY_ENCRYPTION_KEY.parse()?;
        let secret = reference.resolve().map_err(|source| {
            KEY_ENCRYPTION_KEY.error("must resolve through env://NAME or file://PATH", source)
        })?;
        let text = secret
            .utf8()
            .map_err(|source| KEY_ENCRYPTION_KEY.error("must contain UTF-8 text", source))?;
        KeyEncryptionKey::parse(text).map_err(|source| {
            KEY_ENCRYPTION_KEY.error("must contain 32 bytes in unpadded base64url", source)
        })
    }

    /// Uses the operator override, then piqueld's ingress ranges, then no trusted peers.
    fn trusted_proxies() -> Result<Vec<IpNet>, ConfigurationError> {
        let (variable, value) = if let Some(value) = TRUSTED_PROXIES.optional()? {
            (TRUSTED_PROXIES, value)
        } else if let Some(value) = INGRESS_PROXIES.optional()? {
            (INGRESS_PROXIES, value)
        } else {
            return Ok(Vec::new());
        };
        let reason = "must contain comma-separated IP addresses or CIDR ranges";
        value
            .split(',')
            .map(str::trim)
            .filter(|proxy| !proxy.is_empty())
            .map(|proxy| {
                // Choose the syntax before parsing so malformed CIDRs retain their own diagnostic.
                if proxy.contains('/') {
                    proxy
                        .parse::<IpNet>()
                        .map_err(|source| variable.error(reason, source))
                } else {
                    proxy
                        .parse::<IpAddr>()
                        .map(IpNet::from)
                        .map_err(|source| variable.error(reason, source))
                }
            })
            .collect()
    }
}

/// Audit key validation.
#[cfg(test)]
mod tests;
