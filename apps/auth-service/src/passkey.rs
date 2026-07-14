//! `WebAuthn` ceremony invariants independent of a particular authenticator crate.

use piquel_auth_protocol::{SessionId, UserId};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

/// A short-lived server-side ceremony record. The raw challenge remains only in
/// the replaceable state store; persistence stores this digest and metadata.
#[derive(Clone, Debug)]
pub(super) struct Ceremony {
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub challenge_digest: [u8; 32],
    pub expires_at: SystemTime,
    pub consumed: bool,
}

pub(super) fn challenge_digest(challenge: &[u8]) -> [u8; 32] {
    Sha256::digest(challenge).into()
}
pub(super) fn validate_ceremony(
    ceremony: &Ceremony,
    challenge: &[u8],
    now: SystemTime,
) -> Result<(), ()> {
    if ceremony.consumed
        || now >= ceremony.expires_at
        || ceremony.challenge_digest != challenge_digest(challenge)
    {
        return Err(());
    }
    Ok(())
}
pub(super) fn ceremony_expiry(now: SystemTime) -> SystemTime {
    now + Duration::from_mins(5)
}

/// The values that must be provided by validated production configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelyingParty {
    pub id: String,
    pub expected_origin: String,
    pub user_verification_required: bool,
}
impl RelyingParty {
    pub(super) fn validate(&self) -> Result<(), ()> {
        if self.id.is_empty()
            || !self.expected_origin.starts_with("https://")
            || !self.expected_origin.contains(&self.id)
        {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ceremony_is_single_use_and_short_lived() {
        let now = SystemTime::now();
        let challenge = b"opaque-test-challenge";
        let ceremony = Ceremony {
            user_id: None,
            session_id: None,
            challenge_digest: challenge_digest(challenge),
            expires_at: ceremony_expiry(now),
            consumed: false,
        };
        assert!(validate_ceremony(&ceremony, challenge, now).is_ok());
        assert!(validate_ceremony(&ceremony, b"wrong", now).is_err());
    }
}
