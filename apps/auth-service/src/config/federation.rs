//! External identity providers: each one's OAuth credentials, read through its
//! own environment variables.

use sourceorigin_common::{
    Provider,
    config::{ConfigurationError, Origin, SecretReference, Variable},
};
use std::collections::BTreeMap;

/// Maximum provider-assigned client ID length.
const MAX_PROVIDER_CLIENT_ID_LENGTH: usize = 512;

sourceorigin_common::variables! {
    /// The sign-in providers' variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    /// The client ID of auth's GitHub OAuth app. Set, it turns GitHub sign-in on
    /// and requires `AUTH_GITHUB_CLIENT_SECRET`; unset or empty, GitHub is off and
    /// its secret isn't read.
    const GITHUB_CLIENT_ID = "AUTH_GITHUB_CLIENT_ID";
    /// Where to read the GitHub OAuth app's client secret, through `env://NAME` or
    /// `file:///path`. It is read and checked at startup: restart auth after
    /// changing it.
    const GITHUB_CLIENT_SECRET = "AUTH_GITHUB_CLIENT_SECRET";
    /// The client ID of auth's Google OAuth client, as `AUTH_GITHUB_CLIENT_ID` is
    /// GitHub's.
    const GOOGLE_CLIENT_ID = "AUTH_GOOGLE_CLIENT_ID";
    /// Where to read the Google OAuth client's secret, as for
    /// `AUTH_GITHUB_CLIENT_SECRET`.
    const GOOGLE_CLIENT_SECRET = "AUTH_GOOGLE_CLIENT_SECRET";
}

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
    /// Reads optional credentials; configuring either requires both. An empty
    /// client ID turns the provider off whatever the secret says, so a deployment
    /// manifest can set both everywhere and leave the ID empty where the provider
    /// has no app, such as previews (see infra/piqueld.toml).
    fn from_environment(provider: Provider) -> Result<Option<Self>, ConfigurationError> {
        let (id, secret) = Self::variables(provider);
        let client_id = match id.optional()? {
            Some(client_id) if client_id.is_empty() => return Ok(None),
            Some(client_id) => client_id,
            None if secret.optional()?.is_none() => return Ok(None),
            None => {
                return Err(ConfigurationError::Missing {
                    variable: id.name(),
                });
            }
        };
        if client_id.len() > MAX_PROVIDER_CLIENT_ID_LENGTH {
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
