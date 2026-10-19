//! Discovery and the issuer handle every validator and client shares.

use crate::{
    Client, ClientConfig, Clock, KeyCache, Resource, ResourceValidator, SystemClock,
    http::{Authorization, Http, NetworkError},
};
use chrono::{DateTime, Utc};
use piquel_common::protocol::{
    metadata::{OPENID_CONFIGURATION_PATH, ServerMetadata},
    oauth::CodeChallengeMethod,
    sdk::{ErrorCategory, ErrorReason, SdkError},
};
use std::{fmt, sync::Arc};
use thiserror::Error;
use url::Url;

/// The issuer's metadata could not be fetched or used.
///
/// ```
/// use piquel_auth::{
///     DiscoveryError,
///     protocol::sdk::{ErrorCategory, ErrorReason, SdkError},
/// };
///
/// let error = DiscoveryError::PkceUnsupported;
/// assert_eq!(
///     error.code(),
///     SdkError::new(ErrorCategory::Discovery, ErrorReason::PkceUnsupported)
/// );
/// ```
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The configured issuer is not an `https` URL without query or fragment.
    #[error("issuer {0:?} must be an https URL without query or fragment")]
    InvalidIssuer(String),
    /// The metadata endpoint could not be reached.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The response is not a metadata document.
    #[error("issuer metadata is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// The metadata names another issuer; nothing it says can be trusted.
    #[error("metadata names issuer {found:?}, expected {expected:?}")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The `issuer` in the metadata.
        found: String,
    },
    /// An endpoint does not use `https`, so credentials or keys would cross the
    /// network in the clear (OIDC Discovery 1.0 §3).
    #[error("issuer metadata's {0} does not use https")]
    InsecureEndpoint(&'static str),
    /// The issuer does not advertise PKCE with `S256`, which login requires.
    #[error("issuer does not support PKCE with S256")]
    PkceUnsupported,
}

impl DiscoveryError {
    /// The shared SDK error code.
    #[must_use]
    pub const fn code(&self) -> SdkError {
        match self {
            Self::InvalidIssuer(_) => SdkError::category(ErrorCategory::Discovery),
            Self::Network(_) => SdkError::category(ErrorCategory::Network),
            Self::InvalidDocument(_) | Self::InsecureEndpoint(_) => {
                SdkError::new(ErrorCategory::Discovery, ErrorReason::InvalidDocument)
            }
            Self::IssuerMismatch { .. } => {
                SdkError::new(ErrorCategory::Discovery, ErrorReason::IssuerMismatch)
            }
            Self::PkceUnsupported => {
                SdkError::new(ErrorCategory::Discovery, ErrorReason::PkceUnsupported)
            }
        }
    }
}

/// What a discovered issuer shares with its validators and clients.
struct IssuerInner {
    /// The checked metadata.
    metadata: ServerMetadata,
    /// The issuer's signing keys.
    keys: KeyCache,
    /// Client for auth's endpoints.
    http: Http,
    /// Time source for every check.
    clock: Arc<dyn Clock>,
}

/// A discovered issuer: its metadata, signing keys, HTTP client and clock. Cheap to
/// clone; share one per process.
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// use piquel_auth::{Issuer, Resource};
///
/// let issuer = Issuer::discover("https://auth.piquel.fr").await?;
/// assert_eq!(issuer.issuer(), "https://auth.piquel.fr");
/// println!("signs in at {}", issuer.metadata().authorization_endpoint);
/// // Validators and clients share the handle and its key cache.
/// let notes = issuer.resource(Resource::new("notes-api")?);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Issuer(Arc<IssuerInner>);

impl fmt::Debug for Issuer {
    /// Names the issuer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Issuer")
            .field(&self.issuer())
            .finish()
    }
}

/// Configures discovery: an HTTP client and a clock.
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// use std::time::Duration;
///
/// // Auth's endpoints never redirect, so a redirect is refused.
/// let http = reqwest::Client::builder()
///     .timeout(Duration::from_secs(5))
///     .redirect(reqwest::redirect::Policy::none())
///     .build()?;
/// let issuer = piquel_auth::Issuer::builder()
///     .http_client(http)
///     .discover("https://auth.piquel.fr")
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct IssuerBuilder {
    /// Client for every request, or `None` for the default.
    http: Option<reqwest::Client>,
    /// Time source for every check.
    clock: Arc<dyn Clock>,
}

impl Default for IssuerBuilder {
    /// The default HTTP client and the system clock.
    fn default() -> Self {
        Self {
            http: None,
            clock: Arc::new(SystemClock),
        }
    }
}

impl IssuerBuilder {
    /// Sends every request through `http`, for timeouts, proxies or extra trusted
    /// roots. Disable redirects on it: no auth endpoint redirects.
    #[must_use]
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// Reads time from `clock`, to pin it in tests.
    #[must_use]
    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Fetches and checks `issuer`'s metadata. The returned `issuer` must equal the
    /// configured one exactly, and PKCE with `S256` must be supported.
    ///
    /// # Errors
    /// See [`DiscoveryError`].
    pub async fn discover(self, issuer: &str) -> Result<Issuer, DiscoveryError> {
        let url = Issuer::metadata_url(issuer)?;
        let http = match self.http {
            Some(client) => Http::new(client),
            None => Http::default_client()?,
        };
        let reply = http.get(&url, Authorization::None).await?.ok(&url)?;
        let metadata = Issuer::check_metadata(issuer, &reply.body)?;
        Ok(Issuer::new(metadata, http, self.clock))
    }
}

impl Issuer {
    /// Discovers `issuer` with the default HTTP client and the system clock.
    ///
    /// # Errors
    /// See [`DiscoveryError`].
    pub async fn discover(issuer: &str) -> Result<Self, DiscoveryError> {
        IssuerBuilder::default().discover(issuer).await
    }

    /// Configures discovery.
    #[must_use]
    pub fn builder() -> IssuerBuilder {
        IssuerBuilder::default()
    }

    /// Builds the handle from checked metadata.
    pub(crate) fn new(metadata: ServerMetadata, http: Http, clock: Arc<dyn Clock>) -> Self {
        let keys = KeyCache::fetched(metadata.jwks_uri.clone(), http.clone(), clock.clone());
        Self::with_keys(metadata, keys, http, clock)
    }

    /// Builds the handle with an explicit key cache.
    pub(crate) fn with_keys(
        metadata: ServerMetadata,
        keys: KeyCache,
        http: Http,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self(Arc::new(IssuerInner {
            metadata,
            keys,
            http,
            clock,
        }))
    }

    /// Where `issuer` publishes its metadata (OIDC Discovery 1.0 §4.1).
    fn metadata_url(issuer: &str) -> Result<Url, DiscoveryError> {
        let invalid = || DiscoveryError::InvalidIssuer(issuer.to_owned());
        let url = Url::parse(issuer).map_err(|_| invalid())?;
        if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        Url::parse(&format!(
            "{}{OPENID_CONFIGURATION_PATH}",
            issuer.trim_end_matches('/')
        ))
        .map_err(|_| invalid())
    }

    /// Parses a metadata document and checks it belongs to `issuer`.
    pub(crate) fn check_metadata(
        issuer: &str,
        document: &[u8],
    ) -> Result<ServerMetadata, DiscoveryError> {
        let metadata: ServerMetadata =
            serde_json::from_slice(document).map_err(DiscoveryError::InvalidDocument)?;
        if metadata.issuer != issuer {
            return Err(DiscoveryError::IssuerMismatch {
                expected: issuer.to_owned(),
                found: metadata.issuer,
            });
        }
        if !metadata
            .code_challenge_methods_supported
            .contains(&CodeChallengeMethod::S256)
        {
            return Err(DiscoveryError::PkceUnsupported);
        }
        let endpoints = [
            ("authorization_endpoint", &metadata.authorization_endpoint),
            ("token_endpoint", &metadata.token_endpoint),
            ("revocation_endpoint", &metadata.revocation_endpoint),
            ("userinfo_endpoint", &metadata.userinfo_endpoint),
            ("end_session_endpoint", &metadata.end_session_endpoint),
            ("jwks_uri", &metadata.jwks_uri),
        ];
        if let Some((name, _)) = endpoints.iter().find(|(_, url)| url.scheme() != "https") {
            return Err(DiscoveryError::InsecureEndpoint(name));
        }
        Ok(metadata)
    }

    /// The issuer identifier, exactly as tokens carry it in `iss`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.0.metadata.issuer
    }

    /// The checked metadata.
    #[must_use]
    pub fn metadata(&self) -> &ServerMetadata {
        &self.0.metadata
    }

    /// The issuer's signing keys.
    #[must_use]
    pub fn keys(&self) -> &KeyCache {
        &self.0.keys
    }

    /// Validates access tokens for `resource`.
    #[must_use]
    pub fn resource(&self, resource: Resource) -> ResourceValidator {
        ResourceValidator::new(self.clone(), resource)
    }

    /// Signs users in as the client `config` describes.
    #[must_use]
    pub fn client(&self, config: ClientConfig) -> Client {
        Client::new(self.clone(), config)
    }

    /// Client for auth's endpoints.
    pub(crate) fn http(&self) -> &Http {
        &self.0.http
    }

    /// The current time from the injected clock.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.0.clock.now()
    }
}
