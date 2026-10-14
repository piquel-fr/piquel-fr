//! Validated startup configuration, grouped by application.

use crate::passkey::DecoyKey;
use ipnet::IpNet;
use piquel_auth_protocol::{Provider, oauth::Scope};
use piquel_common::{
    ConfigurationError, Origin, PublicUrl, SecretBytes, SecretReference, Variable,
};
use piquel_crypto::{Digest, Rs256Key, Secret};
use piquel_repository::{BootstrapOidcClient, DatabaseConfig};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Maximum provider-assigned client ID length.
const MAX_PROVIDER_CLIENT_ID_LENGTH: usize = 512;
/// Maximum signing-key identifier length.
const MAX_SIGNING_KEY_ID_LENGTH: usize = 128;
/// Identifier used when the operator does not name the primary signing key.
const DEFAULT_SIGNING_KEY_ID: &str = "primary";
/// Separates refresh digests from every other use of the persistent PEM bytes.
const REFRESH_DIGEST_CONTEXT: &[u8] = b"piquel-refresh-token-digest-v1";
/// Separates the passkey decoy key from every other use of the persistent PEM bytes.
const PASSKEY_DECOY_CONTEXT: &[u8] = b"piquel-passkey-decoy-credential-v1";
/// Default number of pooled authentication connections.
const DATABASE_POOL_SIZE: u32 = 10;
/// Maximum startup wait for a pooled database connection.
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Public settings destination when no override is configured.
const DEFAULT_SETTINGS_URL: &str = "https://piquel.fr/settings";
/// Listener address when none is configured; the HTTPS ingress proxies to it.
const DEFAULT_PUBLIC_LISTENER: &str = "127.0.0.1:8080";

/// Authentication origin, shared by all application sections.
pub const PUBLIC_BASE_URL: Variable = Variable::new("AUTH_PUBLIC_BASE_URL");
/// Public settings continuation.
const SETTINGS_URL: Variable = Variable::new("AUTH_SETTINGS_URL");
/// HTTP listener behind the HTTPS ingress.
const PUBLIC_LISTENER: Variable = Variable::new("AUTH_PUBLIC_LISTENER");
/// `PostgreSQL` transport and database.
const DATABASE_URL: Variable = Variable::new("AUTH_DATABASE_URL");
/// Optional separately mounted database password.
const DATABASE_PASSWORD: Variable = Variable::new("AUTH_DATABASE_PASSWORD");
/// Required persistent signing-key reference.
const KEY_PROVIDER: Variable = Variable::new("AUTH_KEY_PROVIDER");
/// Stable public signing-key identifier.
const SIGNING_KEY_ID: Variable = Variable::new("AUTH_SIGNING_KEY_ID");
/// Whether registration requires an invitation.
const INVITE_REQUIRED: Variable = Variable::new("AUTH_INVITE_REQUIRED");
/// Statically reviewed OIDC clients file.
const CLIENTS_FILE: Variable = Variable::new("AUTH_CLIENTS_FILE");
/// Operator-specified trusted ingress peers.
const TRUSTED_PROXIES: Variable = Variable::new("AUTH_TRUSTED_PROXIES");
/// Default ingress peers provided by piqueld.
const INGRESS_PROXIES: Variable = Variable::new("PIQUELD_INGRESS_PROXIES");

/// Passkey relying-party configuration.
#[derive(Clone)]
pub(crate) struct PasskeyConfig {
    /// Exact validated relying-party origin.
    pub origin: Origin,
    /// Registration admission policy.
    pub invite_required: bool,
    /// Domain-separated key for the stable decoy credentials of unknown usernames.
    pub decoy_key: DecoyKey,
}
impl PasskeyConfig {
    /// Reads the passkey policy, validates that the origin has a domain RP ID and
    /// derives the decoy key from the persistent PEM key.
    pub(crate) fn from_environment(
        origin: &Origin,
        persistent_key: &SecretBytes,
    ) -> Result<Self, ConfigurationError> {
        if !matches!(origin.as_url().host(), Some(url::Host::Domain(_))) {
            return Err(PUBLIC_BASE_URL
                .invalid("must use a domain name for WebAuthn, e.g. https://auth.piquel.fr"));
        }
        Ok(Self {
            origin: origin.clone(),
            invite_required: INVITE_REQUIRED.flag(true)?,
            decoy_key: DecoyKey::new(AuthConfig::derive_key(
                persistent_key,
                PASSKEY_DECOY_CONTEXT,
            )?),
        })
    }
}

/// GitHub-assigned client identifier.
const GITHUB_CLIENT_ID: Variable = Variable::new("AUTH_GITHUB_CLIENT_ID");
/// Reference to the GitHub client secret.
const GITHUB_CLIENT_SECRET: Variable = Variable::new("AUTH_GITHUB_CLIENT_SECRET");
/// Google-assigned client identifier.
const GOOGLE_CLIENT_ID: Variable = Variable::new("AUTH_GOOGLE_CLIENT_ID");
/// Reference to the Google client secret.
const GOOGLE_CLIENT_SECRET: Variable = Variable::new("AUTH_GOOGLE_CLIENT_SECRET");

/// OAuth credentials validated before application construction.
#[derive(Clone, Debug)]
pub(crate) struct ProviderConfig {
    /// Provider-assigned client identifier.
    pub client_id: String,
    /// Reference to the client secret.
    pub client_secret: SecretReference,
}

impl ProviderConfig {
    /// Maps every supported provider to its explicit environment contract.
    pub(crate) const fn variables(provider: Provider) -> (Variable, Variable) {
        match provider {
            Provider::GitHub => (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET),
            Provider::Google => (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        }
    }
    /// Reads optional credentials; configuring either requires both.
    fn from_environment(provider: Provider) -> Result<Option<Self>, ConfigurationError> {
        let (id, secret) = Self::variables(provider);
        if id.optional()?.is_none() && secret.optional()?.is_none() {
            return Ok(None);
        }
        let client_id = id.required()?;
        if client_id.is_empty() || client_id.len() > MAX_PROVIDER_CLIENT_ID_LENGTH {
            return Err(id.invalid("must contain 1 to 512 characters assigned by the provider"));
        }
        let client_secret = secret
            .required()?
            .parse()
            .map_err(|source| secret.error("must use env://NAME or file://PATH", source))?;
        Ok(Some(Self {
            client_id,
            client_secret,
        }))
    }
}

/// Social authentication configuration, keyed by the shared provider vocabulary.
#[derive(Clone)]
pub(crate) struct FederationConfig {
    /// Exact provider callback origin.
    pub origin: Origin,
    /// Only permitted external continuation.
    pub settings_url: PublicUrl,
    /// Enabled provider credentials.
    pub providers: BTreeMap<Provider, ProviderConfig>,
}

impl FederationConfig {
    /// Loads every provider through its exhaustive environment mapping.
    pub(crate) fn from_environment(
        origin: &Origin,
        settings_url: &PublicUrl,
    ) -> Result<Self, ConfigurationError> {
        let mut providers = BTreeMap::new();
        for provider in Provider::ALL {
            if let Some(config) = ProviderConfig::from_environment(provider)? {
                providers.insert(provider, config);
            }
        }
        Ok(Self {
            origin: origin.clone(),
            settings_url: settings_url.clone(),
            providers,
        })
    }
}

/// Persistent signing material and the exact OIDC issuer.
#[derive(Clone)]
pub(crate) struct OidcConfig {
    /// Exact HTTPS issuer origin.
    pub origin: Origin,
    /// Key used to sign and verify service JWTs.
    pub keys: Arc<Rs256Key>,
    /// Domain-separated refresh-token HMAC key.
    pub refresh_key: Arc<Secret>,
    /// Client registrations provisioned atomically at startup.
    pub clients: Vec<BootstrapOidcClient>,
    /// Parsed callbacks retained for the public-client origin policy.
    pub public_redirects: Vec<url::Url>,
}

impl OidcConfig {
    /// Parses the persistent signing key and loads statically reviewed clients.
    pub(crate) fn from_environment(
        origin: &Origin,
        secret: &SecretBytes,
    ) -> Result<Self, ConfigurationError> {
        let pem = secret
            .utf8()
            .map_err(|source| KEY_PROVIDER.error("must contain UTF-8 PEM", source))?;
        let kid = SIGNING_KEY_ID
            .optional()?
            .unwrap_or_else(|| DEFAULT_SIGNING_KEY_ID.into());
        if kid.is_empty()
            || kid.len() > MAX_SIGNING_KEY_ID_LENGTH
            || kid.chars().any(char::is_whitespace)
        {
            return Err(
                SIGNING_KEY_ID.invalid("must contain 1 to 128 characters without whitespace")
            );
        }
        let keys = Rs256Key::from_pem(kid, pem).map_err(|source| {
            KEY_PROVIDER.error(
                "must contain an RSA private PEM key of at least 2048 bits",
                source,
            )
        })?;
        let refresh_key = AuthConfig::derive_key(secret, REFRESH_DIGEST_CONTEXT)?;
        let clients = Self::clients()?;
        let public_redirects = clients
            .iter()
            .filter(|client| client.client_secret_hash.is_none())
            .flat_map(|client| &client.redirect_uris)
            .map(|uri| {
                url::Url::parse(uri).map_err(|source| {
                    CLIENTS_FILE.error("redirect_uris must contain absolute HTTPS URLs", source)
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            public_redirects,
            origin: origin.clone(),
            keys: Arc::new(keys),
            refresh_key: Arc::new(refresh_key),
            clients,
        })
    }

    /// Reads and validates clients without exposing confidential secret values.
    fn clients() -> Result<Vec<BootstrapOidcClient>, ConfigurationError> {
        let Some(path) = CLIENTS_FILE.optional()? else {
            return Ok(Vec::new());
        };
        let bytes = std::fs::read(&path).map_err(|source| {
            CLIENTS_FILE.error("must name a readable JSON clients file", source)
        })?;
        let inputs: Vec<ClientConfig> = serde_json::from_slice(&bytes).map_err(|source| {
            CLIENTS_FILE.error("must contain a JSON array of OIDC clients", source)
        })?;
        let clients: Vec<_> = inputs
            .into_iter()
            .map(ClientConfig::into_client)
            .collect::<Result<_, _>>()?;
        let unique: HashSet<_> = clients.iter().map(|client| &client.id).collect();
        if unique.len() != clients.len() {
            return Err(CLIENTS_FILE.invalid("must contain unique client IDs"));
        }
        Ok(clients)
    }
}

/// Client configuration accepted by the reviewed JSON file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    /// Stable client identifier.
    id: String,
    /// Consent-screen name.
    display_name: String,
    /// Authorization callback allowlist.
    redirect_uris: Vec<String>,
    /// Post-logout callback allowlist.
    #[serde(default)]
    post_logout_uris: Vec<String>,
    /// Scope allowlist.
    #[serde(default = "ClientConfig::scopes")]
    allowed_scopes: Vec<String>,
    /// Refresh-token policy.
    #[serde(default)]
    allow_refresh: bool,
    /// Consent bypass policy.
    #[serde(default)]
    trusted: bool,
    /// Startup availability.
    #[serde(default = "ClientConfig::enabled")]
    enabled: bool,
    /// Confidential client secret reference.
    client_secret: Option<String>,
}

impl ClientConfig {
    /// Scopes granted to a client that lists none.
    fn scopes() -> Vec<String> {
        [Scope::OpenId, Scope::Profile, Scope::Email]
            .map(|scope| scope.as_str().to_owned())
            .into()
    }

    /// Clients default to enabled.
    const fn enabled() -> bool {
        true
    }

    /// Resolves secrets, hashes them and validates the repository contract.
    fn into_client(self) -> Result<BootstrapOidcClient, ConfigurationError> {
        let client_secret_hash = self
            .client_secret
            .map(|reference| {
                let secret = SecretReference::parse(&reference)
                    .and_then(|reference| reference.resolve())
                    .map_err(|source| {
                        CLIENTS_FILE.error(
                            "client_secret must resolve through env://NAME or file://PATH",
                            source,
                        )
                    })?;
                let text = secret.utf8().map_err(|source| {
                    CLIENTS_FILE.error("client_secret must contain UTF-8 text", source)
                })?;
                Digest::client_secret(text)
                    .map(|digest| digest.as_bytes().to_vec())
                    .map_err(|source| {
                        CLIENTS_FILE.error(
                            "client_secret must encode at least 32 random bytes (43 to 512 characters)",
                            source,
                        )
                    })
            })
            .transpose()?;
        let client = BootstrapOidcClient {
            allowed_audiences: vec![self.id.clone()],
            id: self.id,
            display_name: self.display_name,
            redirect_uris: self.redirect_uris,
            post_logout_uris: self.post_logout_uris,
            allowed_scopes: self.allowed_scopes,
            allow_refresh: self.allow_refresh,
            trusted: self.trusted,
            enabled: self.enabled,
            client_secret_hash,
        };
        client.validate().map_err(|source| {
            CLIENTS_FILE.error(
                "clients need IDs/scopes in [A-Za-z0-9._-]{1,64}, a nonblank name of at most \
                 80 characters, and 1 to 16 HTTPS redirect URIs without credentials or fragments",
                source,
            )
        })?;
        Ok(client)
    }
}

/// Validated service configuration combining one section per application.
pub struct AuthConfig {
    /// Address bound by the HTTP listener behind piqueld.
    pub public_listener: SocketAddr,
    /// Passkey policy and origin.
    pub(crate) passkey: PasskeyConfig,
    /// External identity provider policy.
    pub(crate) federation: FederationConfig,
    /// OIDC issuer and persistent keys.
    pub(crate) oidc: OidcConfig,
    /// Trusted reverse-proxy peers.
    pub(crate) trusted_proxies: Vec<IpNet>,
}

impl AuthConfig {
    /// Loads the database independently for migration and invitation commands.
    ///
    /// # Errors
    /// Names invalid transport settings or unresolved password references.
    pub fn database_from_environment() -> Result<DatabaseConfig, ConfigurationError> {
        let url = DATABASE_URL.required()?;
        let config = DatabaseConfig::new(&url, DATABASE_POOL_SIZE, DATABASE_CONNECT_TIMEOUT)
            .map_err(|source| {
                DATABASE_URL.error(
                    "must be a postgres:// URL with sslmode=verify-full, explicit \
                     sslmode=disable, or a Unix socket",
                    source,
                )
            })?;
        let Some(reference) = DATABASE_PASSWORD.optional()? else {
            return Ok(config);
        };
        let parsed = url::Url::parse(&url)
            .map_err(|source| DATABASE_URL.error("must be a postgres:// URL", source))?;
        if parsed.password().is_some() {
            return Err(DATABASE_PASSWORD
                .invalid("must be omitted when AUTH_DATABASE_URL contains a password"));
        }
        let secret = SecretReference::parse(&reference)
            .and_then(|reference| reference.resolve())
            .map_err(|source| {
                DATABASE_PASSWORD.error("must resolve through env://NAME or file://PATH", source)
            })?;
        let password = secret
            .utf8()
            .map_err(|source| DATABASE_PASSWORD.error("must contain UTF-8 text", source))?;
        Ok(config.with_password(password.trim_end_matches('\n')))
    }

    /// Validates all service and application settings before startup.
    ///
    /// # Errors
    /// Names invalid or missing variables and retains safe underlying sources.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        let origin: Origin = PUBLIC_BASE_URL.parse()?;
        let settings_url: PublicUrl = SETTINGS_URL.parse_or(DEFAULT_SETTINGS_URL)?;
        let persistent_key: SecretReference = KEY_PROVIDER.parse()?;
        let persistent_key = persistent_key.resolve().map_err(|source| {
            KEY_PROVIDER.error(
                "must resolve to an RSA private PEM key of at least 2048 bits",
                source,
            )
        })?;
        Ok(Self {
            public_listener: PUBLIC_LISTENER.parse_or(DEFAULT_PUBLIC_LISTENER)?,
            passkey: PasskeyConfig::from_environment(&origin, &persistent_key)?,
            federation: FederationConfig::from_environment(&origin, &settings_url)?,
            oidc: OidcConfig::from_environment(&origin, &persistent_key)?,
            trusted_proxies: Self::trusted_proxies()?,
        })
    }

    /// Derives a service key from the persistent PEM bytes under its own `context`,
    /// so each key is stable across restarts and replicas but independent of the others.
    fn derive_key(
        persistent_key: &SecretBytes,
        context: &[u8],
    ) -> Result<Secret, ConfigurationError> {
        Secret::derive(persistent_key.expose_secret(), context)
            .map_err(|source| KEY_PROVIDER.error("could not derive a key from the PEM key", source))
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
