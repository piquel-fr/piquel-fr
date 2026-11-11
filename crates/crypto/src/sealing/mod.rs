//! AES-256-GCM sealing of private keys at rest under a key-encryption key (KEK).
use super::{CryptoError, Secret};
use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use std::fmt;

/// The key that seals signing keys in the database, from configuration. Sealed
/// values are `nonce || ciphertext || tag`; the associated data binds each one to
/// the record it belongs to, so a sealed key moved to another record fails to open.
pub struct KeyEncryptionKey(Secret);

impl KeyEncryptionKey {
    /// Parses the KEK from its configured text: 32 bytes in unpadded base64url. A
    /// trailing newline, as files often end with, is ignored.
    ///
    /// # Errors
    /// Rejects other encodings and lengths other than 32 bytes.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        Secret::parse(text.strip_suffix('\n').unwrap_or(text)).map(Self)
    }

    /// Generates a KEK, for tests and development.
    ///
    /// # Errors
    /// Preserves failures from the random source.
    pub fn generate() -> Result<Self, CryptoError> {
        Secret::generate().map(Self)
    }

    /// Encrypts `plaintext`, authenticating `aad` with it.
    ///
    /// # Errors
    /// Preserves failures from the random source and the cryptographic provider.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sealed = plaintext.to_vec();
        let nonce = self
            .key()?
            .seal_in_place_append_tag(Aad::from(aad), &mut sealed)?;
        Ok([nonce.as_ref().as_slice(), &sealed].concat())
    }

    /// Decrypts a value [`Self::seal`] made with the same KEK and `aad`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Unsealable`] for another KEK, other associated data or
    /// a modified value.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (nonce, rest) = sealed
            .split_at_checked(NONCE_LEN)
            .ok_or(CryptoError::Unsealable)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let mut opened = rest.to_vec();
        // A failed tag check says nothing more than this variant does.
        let plaintext = self
            .key()?
            .open_in_place(nonce, Aad::from(aad), &mut opened)
            .map_err(|_| CryptoError::Unsealable)?;
        Ok(plaintext.to_vec())
    }

    /// The AES-256-GCM key, which draws a random nonce for every seal.
    fn key(&self) -> Result<RandomizedNonceKey, CryptoError> {
        Ok(RandomizedNonceKey::new(&AES_256_GCM, self.0.as_bytes())?)
    }
}

impl fmt::Debug for KeyEncryptionKey {
    /// Renders a safe diagnostic representation without exposing the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyEncryptionKey(REDACTED)")
    }
}

#[cfg(test)]
mod tests;
