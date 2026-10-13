//! Stable decoy credentials, so username sign-in does not reveal which accounts exist.
//!
//! A username without an active account or passkey still receives a challenge listing
//! credentials. They are derived from the username with a server key, so they stay the
//! same across requests, restarts and replicas, as a real account's credentials do.
//! Nobody holds their private keys, and their ceremony fails at finish regardless.

use super::{PasskeyApplication, PasskeyError};
use piquel_crypto::{Digest, Secret};
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
/// IDs use one-byte inputs instead, so the public IDs reveal nothing about this choice.
const DECOY_SHAPE_INPUT: &[u8] = b"shape";

impl PasskeyApplication {
    /// Returns the stable `allowCredentials` for a username with no active account or passkey.
    pub(super) fn decoy_credentials(
        &self,
        username: &str,
    ) -> Result<Vec<AllowCredentials>, PasskeyError> {
        let key = Secret::derive(self.decoy_key.as_bytes(), username.as_bytes())?;
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
