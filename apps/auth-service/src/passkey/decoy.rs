//! Stable decoy credentials, so username sign-in does not reveal which accounts exist.
//!
//! A username without an active account or passkey still receives a challenge listing
//! credentials. They are derived from the username with a server key, so they stay the
//! same across requests, restarts and replicas, as a real account's credentials do.
//! Nobody holds their private keys, and their ceremony fails at finish regardless.

use piquel_crypto::{CryptoError, Digest, Secret};
use webauthn_rs_proto::AllowCredentials;

/// Credential type of every `WebAuthn` descriptor, as webauthn-rs writes it.
const PUBLIC_KEY_CREDENTIAL_TYPE: &str = "public-key";
/// Decoy credential counts, each equally likely: most accounts hold one passkey.
const DECOY_COUNTS: [u8; 4] = [1, 1, 1, 2];
/// Decoy credential ID lengths, each equally likely. Common synced passkeys use 16
/// (such as Google Password Manager) or 20 bytes (iCloud Keychain); others use 32.
/// Decoys hide accounts whose credentials match these shapes, so keep them close to
/// the real mix. No decoy lists transports: webauthn-rs keeps them only from packed or
/// TPM attestation, and browsers replace both with `none`, which passkey registration requests.
const DECOY_ID_LENGTHS: [usize; 3] = [16, 20, 32];
/// Input under a username's key that selects its decoy count and ID lengths. Credential
/// IDs use one-byte inputs instead, so ID bytes are independent of the chosen shape.
const DECOY_SHAPE_INPUT: &[u8] = b"shape";

// Each ID is a prefix of one digest, and the shape digest holds the count byte followed
// by one length byte per credential, so the indexing in `DecoyKey::credentials` is in bounds.
const _: () = {
    let mut index = 0;
    while index < DECOY_ID_LENGTHS.len() {
        assert!(DECOY_ID_LENGTHS[index] <= Digest::LENGTH);
        index += 1;
    }
    index = 0;
    while index < DECOY_COUNTS.len() {
        assert!((DECOY_COUNTS[index] as usize) < Digest::LENGTH);
        index += 1;
    }
};

/// HMAC key deriving the decoy credentials of usernames without an active account or
/// passkey. It must be derived from persistent key material, so decoys stay stable.
#[derive(Clone)]
pub(crate) struct DecoyKey(Secret);

impl DecoyKey {
    /// Wraps a key reserved for decoy credentials.
    pub(crate) const fn new(key: Secret) -> Self {
        Self(key)
    }

    /// Returns the stable `allowCredentials` for `username`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn credentials(&self, username: &str) -> Result<Vec<AllowCredentials>, CryptoError> {
        let key = Secret::derive(self.0.as_bytes(), username.as_bytes())?;
        let shape = Digest::hmac(key.as_bytes(), DECOY_SHAPE_INPUT)?;
        let [count, lengths @ ..] = shape.as_bytes();
        (0..DECOY_COUNTS[usize::from(*count) % DECOY_COUNTS.len()])
            .map(|index| {
                let length = DECOY_ID_LENGTHS
                    [usize::from(lengths[usize::from(index)]) % DECOY_ID_LENGTHS.len()];
                Ok(AllowCredentials {
                    type_: PUBLIC_KEY_CREDENTIAL_TYPE.into(),
                    id: Digest::hmac(key.as_bytes(), &[index])?.as_bytes()[..length]
                        .to_vec()
                        .into(),
                    transports: None,
                })
            })
            .collect()
    }
}

/// Decoy shapes without a database.
#[cfg(test)]
mod tests {
    use super::{DECOY_COUNTS, DECOY_ID_LENGTHS, DecoyKey, PUBLIC_KEY_CREDENTIAL_TYPE};
    use piquel_crypto::Secret;
    use std::collections::HashSet;
    use webauthn_rs_proto::AllowCredentials;

    /// Across many usernames, decoys use every configured count and ID length and
    /// nothing else, and a username always gets the same decoys.
    #[test]
    fn decoys_use_exactly_the_configured_shapes() {
        let key = DecoyKey::new(Secret::generate().expect("key"));
        let (mut counts, mut lengths) = (HashSet::new(), HashSet::new());
        for index in 0..256 {
            let username = format!("user_{index}");
            let ids = |decoys: &[AllowCredentials]| {
                decoys
                    .iter()
                    .map(|decoy| decoy.id.clone())
                    .collect::<Vec<_>>()
            };
            let decoys = key.credentials(&username).expect("decoys");
            let repeated = key.credentials(&username).expect("decoys");
            assert_eq!(ids(&decoys), ids(&repeated));
            counts.insert(u8::try_from(decoys.len()).expect("count"));
            for decoy in decoys {
                assert_eq!(decoy.type_, PUBLIC_KEY_CREDENTIAL_TYPE);
                assert!(decoy.transports.is_none());
                lengths.insert(decoy.id.len());
            }
        }
        assert_eq!(counts, DECOY_COUNTS.into_iter().collect());
        assert_eq!(lengths, DECOY_ID_LENGTHS.into_iter().collect());
    }
}
