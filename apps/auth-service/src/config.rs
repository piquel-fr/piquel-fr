//! Validated startup configuration, grouped by application.

use crate::{emails::VerificationKey, passkey::DecoyKey, recovery::RecoveryLinks};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
use lettre::{
    AsyncSmtpTransport, Tokio1Executor,
    message::Mailbox,
    transport::smtp::{authentication::Credentials, extension::ClientId},
};
use piquel_common::{
    Provider,
    config::{ConfigurationError, Origin, SecretBytes, SecretReference, Variable},
};
use piquel_crypto::{CryptoError, Digest, KeyEncryptionKey, Secret};
use piquel_repository::{DatabaseConfig, RuntimeRole};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Maximum provider-assigned client ID length.
const MAX_PROVIDER_CLIENT_ID_LENGTH: usize = 512;
/// Separates opaque token digests from every other use of a token digest key. The
/// PEM signing key was used the same way, so it still works as a token digest key.
const TOKEN_DIGEST_CONTEXT: &[u8] = b"piquel-refresh-token-digest-v1";
/// Separates the passkey decoy key from every other use of the current token
/// digest key. The PEM signing key was used the same way, so decoys stay the same
/// while it is the current key.
const PASSKEY_DECOY_CONTEXT: &[u8] = b"piquel-passkey-decoy-credential-v1";
/// Separates the email verification key from every other use of the current token
/// digest key, as [`PASSKEY_DECOY_CONTEXT`] does the decoy key.
const EMAIL_VERIFICATION_CONTEXT: &[u8] = b"piquel-email-verification-token-v1";
/// Separates the recovery link key from every other use of the current token
/// digest key, as [`PASSKEY_DECOY_CONTEXT`] does the decoy key.
const RECOVERY_LINK_CONTEXT: &[u8] = b"piquel-account-recovery-link-v1";
/// Fewest bytes a token digest key may have.
const MIN_TOKEN_DIGEST_KEY_BYTES: usize = 32;
/// Bytes of a token digest key's digest kept as its fingerprint.
const DIGEST_KEY_FINGERPRINT_BYTES: usize = 8;
/// Default number of pooled authentication connections.
const DATABASE_POOL_SIZE: u32 = 10;
/// Maximum startup wait for a pooled database connection.
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Listener address when none is configured; the HTTPS ingress proxies to it.
const DEFAULT_PUBLIC_LISTENER: &str = "127.0.0.1:8080";

/// Authentication origin, shared by all application sections.
pub const PUBLIC_BASE_URL: Variable = Variable::new("AUTH_PUBLIC_BASE_URL");
/// HTTP listener behind the HTTPS ingress.
const PUBLIC_LISTENER: Variable = Variable::new("AUTH_PUBLIC_LISTENER");
/// Optional listener serving only the admin dashboard, which only a private route
/// may reach.
const ADMIN_LISTENER: Variable = Variable::new("AUTH_ADMIN_LISTENER");
/// The admin dashboard's origin, e.g. `https://admin.piquel.fr`, set with
/// [`ADMIN_LISTENER`].
const ADMIN_ORIGIN: Variable = Variable::new("AUTH_ADMIN_ORIGIN");
/// `PostgreSQL` transport and database.
const DATABASE_URL: Variable = Variable::new("AUTH_DATABASE_URL");
/// Optional separately mounted database password.
const DATABASE_PASSWORD: Variable = Variable::new("AUTH_DATABASE_PASSWORD");
/// Optional schema owner `migrate` connects as, to provision the runtime role.
const DATABASE_OWNER_URL: Variable = Variable::new("AUTH_DATABASE_OWNER_URL");
/// Optional separately mounted schema owner password.
const DATABASE_OWNER_PASSWORD: Variable = Variable::new("AUTH_DATABASE_OWNER_PASSWORD");
/// The connection every command uses.
const RUNTIME_DATABASE: DatabaseVariables = DatabaseVariables {
    url: DATABASE_URL,
    password: DATABASE_PASSWORD,
};
/// The schema owner's connection, used only by `migrate`.
const OWNER_DATABASE: DatabaseVariables = DatabaseVariables {
    url: DATABASE_OWNER_URL,
    password: DATABASE_OWNER_PASSWORD,
};
/// Reference to the key that seals signing keys in the database.
const KEY_ENCRYPTION_KEY: Variable = Variable::new("AUTH_KEY_ENCRYPTION_KEY");
/// Reference to the key under which opaque token secrets are digested.
const TOKEN_DIGEST_KEY: Variable = Variable::new("AUTH_TOKEN_DIGEST_KEY");
/// Optional reference to another token digest key, accepted but never used for
/// new digests: the next key before it is current, or the old one after.
const TOKEN_DIGEST_KEY_ACCEPTED: Variable = Variable::new("AUTH_TOKEN_DIGEST_KEY_ACCEPTED");
/// The removed PEM signing key and its ID. Startup refuses them, so a deployment
/// that still sets them learns that signing keys now live in the database.
const REMOVED_KEY_VARIABLES: [Variable; 2] = [
    Variable::new("AUTH_KEY_PROVIDER"),
    Variable::new("AUTH_SIGNING_KEY_ID"),
];
/// Whether registration requires an invitation.
const INVITE_REQUIRED: Variable = Variable::new("AUTH_INVITE_REQUIRED");
/// The removed OIDC clients file. Startup refuses it, so a deployment that still
/// sets it fails loudly instead of silently serving without its clients.
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
    /// derives the decoy key from the token digest key.
    pub(crate) fn from_environment(
        origin: &Origin,
        digest_keys: &TokenDigestKeys,
    ) -> Result<Self, ConfigurationError> {
        if !matches!(origin.as_url().host(), Some(url::Host::Domain(_))) {
            return Err(PUBLIC_BASE_URL
                .invalid("must use a domain name for WebAuthn, e.g. https://auth.piquel.fr"));
        }
        Ok(Self {
            origin: origin.clone(),
            invite_required: INVITE_REQUIRED.flag(true)?,
            decoy_key: DecoyKey::new(digest_keys.current.decoy.clone()),
        })
    }
}

/// SMTP relay: `smtps://user@host:465`, or `smtp://user@host:587` with STARTTLS.
/// Unset, email is disabled.
const SMTP_URL: Variable = Variable::new("AUTH_SMTP_URL");
/// Reference to the SMTP password of the URL's user.
const SMTP_PASSWORD: Variable = Variable::new("AUTH_SMTP_PASSWORD");
/// The sender of every message.
const EMAIL_FROM: Variable = Variable::new("AUTH_EMAIL_FROM");
/// The sender when none is configured.
const DEFAULT_EMAIL_FROM: &str = "Piquel <security@piquel.fr>";
/// Port of `smtps://` URLs without one: SMTP submission over implicit TLS.
const SMTPS_PORT: u16 = 465;
/// Port of `smtp://` URLs without one: SMTP submission, upgraded with STARTTLS.
const SUBMISSION_PORT: u16 = 587;
/// The longest one SMTP command may take, like an outbound HTTP request.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Email to account holders: where it is sent, as whom, and the keys of its
/// verification and recovery links.
#[derive(Clone)]
pub(crate) struct EmailConfig {
    /// The SMTP relay; `None` when `AUTH_SMTP_URL` is unset, which disables email.
    pub smtp: Option<AsyncSmtpTransport<Tokio1Executor>>,
    /// The `From` of every message.
    pub from: Mailbox,
    /// Auth's origin, whose settings pages every link in a message opens.
    pub origin: Origin,
    /// Derives verification tokens from address IDs.
    pub verification_key: VerificationKey,
    /// Derives recovery links from recovery IDs.
    pub recovery_links: RecoveryLinks,
}

impl EmailConfig {
    /// Reads the relay and sender, and derives the verification key from the
    /// token digest key.
    fn from_environment(
        origin: &Origin,
        digest_keys: &TokenDigestKeys,
    ) -> Result<Self, ConfigurationError> {
        let smtp = match SMTP_URL.optional()? {
            Some(url) => Some(Self::relay(&url, origin)?),
            None if SMTP_PASSWORD.optional()?.is_some() => {
                return Err(SMTP_PASSWORD.invalid("needs AUTH_SMTP_URL, which is unset"));
            }
            None => None,
        };
        Ok(Self {
            smtp,
            from: EMAIL_FROM.parse_or(DEFAULT_EMAIL_FROM)?,
            origin: origin.clone(),
            verification_key: VerificationKey::new(digest_keys.current.verification.clone()),
            recovery_links: digest_keys.recovery_links(origin),
        })
    }

    /// Builds the relay `url` names. `smtps://` uses implicit TLS, `smtp://`
    /// requires STARTTLS, both with verified certificates. Only a loopback host,
    /// such as a local Mailpit, may be reached without TLS, since plaintext never
    /// leaves the machine. The password comes from `AUTH_SMTP_PASSWORD`, never
    /// from the URL. The service greets the relay with the auth origin's host.
    fn relay(
        url: &str,
        origin: &Origin,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, ConfigurationError> {
        let usage = "must be smtps://USER@HOST[:PORT] or smtp://USER@HOST[:PORT], \
                     without a password, path, query or fragment";
        let url = url::Url::parse(url).map_err(|source| SMTP_URL.error(usage, source))?;
        // `url` only types a bracketed IPv6 host for schemes it does not know, such
        // as `smtp`: an IPv4 address or `LOCALHOST` stays text, parsed here. IPv6
        // reaches lettre without its brackets.
        let host = match url.host().ok_or_else(|| SMTP_URL.invalid(usage))? {
            url::Host::Ipv6(ip) => ip.to_string(),
            host => host.to_string(),
        };
        let loopback = match host.parse::<IpAddr>() {
            Ok(ip) => ip.is_loopback(),
            Err(_) => host.eq_ignore_ascii_case("localhost"),
        };
        if url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(SMTP_URL.invalid(usage));
        }
        let builder = match url.scheme() {
            "smtps" => AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                .map_err(|source| SMTP_URL.error("could not set up TLS", source))?
                .port(url.port().unwrap_or(SMTPS_PORT)),
            "smtp" if loopback => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                .port(url.port().unwrap_or(SUBMISSION_PORT)),
            "smtp" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|source| SMTP_URL.error("could not set up TLS", source))?
                .port(url.port().unwrap_or(SUBMISSION_PORT)),
            _ => return Err(SMTP_URL.invalid(usage)),
        };
        let builder = builder
            .timeout(Some(SMTP_TIMEOUT))
            .hello_name(ClientId::Domain(origin.host().to_owned()));
        let password = SMTP_PASSWORD.optional()?;
        Ok(match (url.username(), password) {
            ("", None) => builder.build(),
            ("", Some(_)) => {
                return Err(
                    SMTP_PASSWORD.invalid("needs a user in AUTH_SMTP_URL, e.g. smtps://USER@HOST")
                );
            }
            (_, None) => {
                return Err(SMTP_PASSWORD.invalid("is required when AUTH_SMTP_URL names a user"));
            }
            (user, Some(reference)) => {
                let user = percent_encoding::percent_decode_str(user)
                    .decode_utf8()
                    .map_err(|source| SMTP_URL.error("must hold a UTF-8 user", source))?
                    .into_owned();
                let password = SecretReference::parse(&reference)
                    .and_then(|reference| reference.resolve())
                    .map_err(|source| {
                        SMTP_PASSWORD
                            .error("must resolve through env://NAME or file://PATH", source)
                    })?;
                let password = password
                    .utf8()
                    .map_err(|source| SMTP_PASSWORD.error("must contain UTF-8 text", source))?
                    .trim_end_matches('\n')
                    .to_owned();
                builder
                    .credentials(Credentials::new(user, password))
                    .build()
            }
        })
    }
}

#[cfg(test)]
impl ProviderConfig {
    /// Test credentials whose secret is read from the file at `secret`.
    pub(crate) fn test(secret: &std::path::Path) -> Self {
        Self {
            client_id: "test-client".into(),
            client_secret: SecretReference::parse(&format!("file://{}", secret.display()))
                .expect("secret reference"),
        }
    }
}

#[cfg(test)]
impl EmailConfig {
    /// Test settings at `origin`, with fresh verification and recovery keys and
    /// recovery links on it. `enabled` sets a relay that tests never reach, so
    /// accounts can add addresses.
    pub(crate) fn test(origin: &Origin, enabled: bool) -> Self {
        Self {
            smtp: enabled.then(|| {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost").build()
            }),
            from: DEFAULT_EMAIL_FROM.parse().expect("sender"),
            origin: origin.clone(),
            verification_key: VerificationKey::new(Secret::generate().expect("verification key")),
            recovery_links: RecoveryLinks::new(
                origin.clone(),
                Secret::generate().expect("recovery key"),
                None,
            ),
        }
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
    /// Enabled provider credentials.
    pub providers: BTreeMap<Provider, ProviderConfig>,
}

impl FederationConfig {
    /// Loads every provider through its exhaustive environment mapping.
    pub(crate) fn from_environment(origin: &Origin) -> Result<Self, ConfigurationError> {
        let mut providers = BTreeMap::new();
        for provider in Provider::ALL {
            if let Some(config) = ProviderConfig::from_environment(provider)? {
                providers.insert(provider, config);
            }
        }
        Ok(Self {
            origin: origin.clone(),
            providers,
        })
    }
}

/// One key under which opaque token secrets are stored as HMAC digests.
pub(crate) struct TokenDigestKey {
    /// The HMAC key, derived from the configured bytes.
    key: Secret,
    /// Identifies the key in stored records, without revealing it.
    fingerprint: String,
    /// The passkey decoy key, derived from the same bytes, used only while this
    /// key is current.
    decoy: Secret,
    /// The email verification key, derived and used like [`Self::decoy`].
    verification: Secret,
    /// The recovery link key, derived and used like [`Self::decoy`].
    recovery: Secret,
}

impl TokenDigestKey {
    /// Derives the HMAC, decoy, verification and recovery link keys from
    /// configured bytes, as the PEM key's always were.
    pub(crate) fn derive(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = Secret::derive(bytes, TOKEN_DIGEST_CONTEXT)?;
        let fingerprint = URL_SAFE_NO_PAD
            .encode(&Digest::sha256(key.as_bytes()).as_bytes()[..DIGEST_KEY_FINGERPRINT_BYTES]);
        Ok(Self {
            key,
            fingerprint,
            decoy: Secret::derive(bytes, PASSKEY_DECOY_CONTEXT)?,
            verification: Secret::derive(bytes, EMAIL_VERIFICATION_CONTEXT)?,
            recovery: Secret::derive(bytes, RECOVERY_LINK_CONTEXT)?,
        })
    }

    /// The digest of `secret` under this key.
    fn digest(&self, secret: &Secret) -> Result<Digest, CryptoError> {
        Digest::hmac(self.key.as_bytes(), secret.as_bytes())
    }
}

/// The token digest keys: the current one makes every new digest, and during a
/// change of key another one is accepted too. A change takes two deploys, so a
/// release never issues a digest the release beside it cannot check: the first
/// accepts the next key, the second makes it current and accepts the old one.
pub struct TokenDigestKeys {
    /// Makes new digests.
    current: TokenDigestKey,
    /// Also accepted.
    accepted: Option<TokenDigestKey>,
}

impl TokenDigestKeys {
    /// Recovery links on `origin`, under the current key's recovery key, and
    /// rebuilt under the accepted one's for recoveries started before a change.
    pub(crate) fn recovery_links(&self, origin: &Origin) -> RecoveryLinks {
        let accepted = self.accepted.as_ref().map(|key| key.recovery.clone());
        RecoveryLinks::new(origin.clone(), self.current.recovery.clone(), accepted)
    }

    /// Uses `current` for new digests and accepts `accepted` too.
    pub(crate) const fn new(current: TokenDigestKey, accepted: Option<TokenDigestKey>) -> Self {
        Self { current, accepted }
    }

    /// Reads `AUTH_TOKEN_DIGEST_KEY` and `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`.
    ///
    /// # Errors
    /// Names a missing or unreadable key, or one shorter than 32 bytes.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        let derive = |variable: Variable, bytes: SecretBytes| {
            TokenDigestKey::derive(bytes.expose_secret())
                .map_err(|source| variable.error("could not derive a key", source))
        };
        let current = derive(TOKEN_DIGEST_KEY, Self::read(TOKEN_DIGEST_KEY)?)?;
        let accepted = TOKEN_DIGEST_KEY_ACCEPTED
            .optional()?
            .map(|_| {
                derive(
                    TOKEN_DIGEST_KEY_ACCEPTED,
                    Self::read(TOKEN_DIGEST_KEY_ACCEPTED)?,
                )
            })
            .transpose()?;
        Ok(Self::new(current, accepted))
    }

    /// Resolves the key `variable` references; its raw bytes are the key.
    fn read(variable: Variable) -> Result<SecretBytes, ConfigurationError> {
        let reference: SecretReference = variable.parse()?;
        let bytes = reference.resolve().map_err(|source| {
            variable.error("must resolve through env://NAME or file://PATH", source)
        })?;
        if bytes.expose_secret().len() < MIN_TOKEN_DIGEST_KEY_BYTES {
            return Err(variable.invalid("must contain at least 32 bytes"));
        }
        Ok(bytes)
    }

    /// The digest a new `secret` is stored as, and its key's fingerprint.
    pub(crate) fn issue(&self, secret: &Secret) -> Result<(Digest, &str), CryptoError> {
        Ok((self.current.digest(secret)?, &self.current.fingerprint))
    }

    /// Every digest a presented `secret` may be stored as, one per accepted key.
    pub(crate) fn accepted(&self, secret: &Secret) -> Result<Vec<Vec<u8>>, CryptoError> {
        [Some(&self.current), self.accepted.as_ref()]
            .into_iter()
            .flatten()
            .map(|key| Ok(key.digest(secret)?.as_bytes().to_vec()))
            .collect()
    }

    /// Names the key a stored fingerprint belongs to: `current`, `accepted`,
    /// `unrecorded` for digests made before fingerprints were stored, under the
    /// PEM key's derivation, or `unknown`.
    #[must_use]
    pub fn name(&self, fingerprint: Option<&str>) -> &'static str {
        let Some(fingerprint) = fingerprint else {
            return "unrecorded";
        };
        if fingerprint == self.current.fingerprint {
            "current"
        } else if self
            .accepted
            .as_ref()
            .is_some_and(|accepted| fingerprint == accepted.fingerprint)
        {
            "accepted"
        } else {
            "unknown"
        }
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
}

/// A database connection's URL variable and its optional password variable.
#[derive(Clone, Copy)]
struct DatabaseVariables {
    /// `PostgreSQL` transport, database and user.
    url: Variable,
    /// Separately mounted password, for URLs without one.
    password: Variable,
}

impl DatabaseVariables {
    /// Reads the connection to `url`, the value of [`Self::url`], and returns it
    /// with its separately mounted password.
    fn read(self, url: &str) -> Result<(DatabaseConfig, Option<String>), ConfigurationError> {
        let config = DatabaseConfig::new(url, DATABASE_POOL_SIZE, DATABASE_CONNECT_TIMEOUT)
            .map_err(|source| {
                self.url.error(
                    "must be a postgres:// URL with sslmode=verify-full, explicit \
                     sslmode=disable, or a Unix socket",
                    source,
                )
            })?;
        let Some(reference) = self.password.optional()? else {
            return Ok((config, None));
        };
        let parsed = url::Url::parse(url)
            .map_err(|source| self.url.error("must be a postgres:// URL", source))?;
        if parsed.password().is_some() {
            return Err(self
                .password
                .invalid("must be omitted when the database URL contains a password"));
        }
        let secret = SecretReference::parse(&reference)
            .and_then(|reference| reference.resolve())
            .map_err(|source| {
                self.password
                    .error("must resolve through env://NAME or file://PATH", source)
            })?;
        let password = secret
            .utf8()
            .map_err(|source| self.password.error("must contain UTF-8 text", source))?
            .trim_end_matches('\n')
            .to_owned();
        Ok((config.with_password(&password), Some(password)))
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
    /// Trusted reverse-proxy peers.
    pub(crate) trusted_proxies: Vec<IpNet>,
}

impl AuthConfig {
    /// Loads the runtime connection, which every command but an owner `migrate` uses.
    ///
    /// # Errors
    /// Names invalid transport settings or unresolved password references.
    pub fn database_from_environment() -> Result<DatabaseConfig, ConfigurationError> {
        Ok(RUNTIME_DATABASE.read(&DATABASE_URL.required()?)?.0)
    }

    /// Loads what `migrate` connects with: the schema owner when
    /// `AUTH_DATABASE_OWNER_URL` is set, along with the runtime role it then
    /// provisions, `AUTH_DATABASE_URL`'s user with `AUTH_DATABASE_PASSWORD`.
    /// Otherwise, the runtime connection alone.
    ///
    /// # Errors
    /// Names invalid transport settings, unresolved password references, or a
    /// runtime role that cannot be provisioned.
    pub fn migration_from_environment()
    -> Result<(DatabaseConfig, Option<RuntimeRole>), ConfigurationError> {
        let (runtime, password) = RUNTIME_DATABASE.read(&DATABASE_URL.required()?)?;
        let Some(url) = DATABASE_OWNER_URL.optional()? else {
            return Ok((runtime, None));
        };
        let (owner, _) = OWNER_DATABASE.read(&url)?;
        let password = password.ok_or(DATABASE_PASSWORD.invalid(
            "must be set with AUTH_DATABASE_OWNER_URL, for the runtime role, and \
             AUTH_DATABASE_URL must then omit its password",
        ))?;
        let role = RuntimeRole::new(&runtime, &password).map_err(|source| {
            DATABASE_URL.error("must name a role migrate can provision", source)
        })?;
        Ok((owner, Some(role)))
    }

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
            passkey: PasskeyConfig::from_environment(&origin, &digest_keys)?,
            federation: FederationConfig::from_environment(&origin)?,
            email: EmailConfig::from_environment(&origin, &digest_keys)?,
            oidc: OidcConfig {
                origin,
                digest_keys,
            },
            key_encryption_key: Arc::new(Self::key_encryption_key_from_environment()?),
            trusted_proxies: Self::trusted_proxies()?,
        })
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
