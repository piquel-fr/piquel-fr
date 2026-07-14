//! Approved-provider identity-linking invariants.

use piquel_auth_protocol::UserId;

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
}
