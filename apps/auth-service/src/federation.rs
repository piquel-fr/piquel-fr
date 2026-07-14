//! Approved-provider identity-linking invariants.

use piquel_auth_protocol::UserId;
use piquel_configuration::SecretReference;

/// The only approved social identity providers in the first iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Provider {
    /// GitHub's OAuth identity API with verified-email lookup.
    GitHub,
    /// Google's `OpenID` Connect identity API.
    Google,
}

impl Provider {
    /// Stable provider label stored in the database.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }

    /// Expected issuer used as the durable external identity namespace.
    pub(super) const fn issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Google => "https://accounts.google.com",
        }
    }
}

/// Provider-specific configuration, with client secrets held only by references.
#[derive(Clone, Debug)]
pub(super) struct ProviderConfiguration {
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: SecretReference,
}

/// Provider claims after issuer/signature/nonce verification by the adapter.
pub(super) struct VerifiedProviderIdentity {
    pub issuer: String,
    pub subject: String,
    pub verified_email: String,
}
/// Linking is permitted only for a stable issuer/subject and an asserted verified email.
pub(super) fn validate_identity(
    identity: &VerifiedProviderIdentity,
    approved_issuer: &str,
) -> Result<(), ()> {
    if identity.issuer != approved_issuer
        || identity.subject.is_empty()
        || identity.subject.len() > 255
        || identity.verified_email.is_empty()
    {
        return Err(());
    }
    Ok(())
}
/// A durable mapping always uses issuer/subject rather than email.
pub(super) struct IdentityLink {
    pub user_id: UserId,
    pub issuer: String,
    pub subject: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_identity_cannot_be_email_only() {
        assert!(
            validate_identity(
                &VerifiedProviderIdentity {
                    issuer: "https://issuer".into(),
                    subject: String::new(),
                    verified_email: "a@example.com".into()
                },
                "https://issuer"
            )
            .is_err()
        );
    }

    #[test]
    fn provider_set_is_explicit_and_stable() {
        assert_eq!(Provider::GitHub.name(), "github");
        assert_eq!(Provider::Google.issuer(), "https://accounts.google.com");
    }
}
