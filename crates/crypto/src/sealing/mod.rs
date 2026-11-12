//! AES-256-GCM sealing: of private keys at rest under the key-encryption key (KEK),
//! and of the SDK's cookies under keys derived from the application's cookie key.
use super::{CryptoError, Secret};
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey},
    hkdf::{HKDF_SHA256, Salt},
};
use secrecy::zeroize::Zeroizing;
use std::fmt;

/// An AES-256-GCM key that seals values as `nonce || ciphertext || tag`, with a
/// random nonce for every seal. The associated data binds each value to its
/// context, so a value moved to another context fails to open.
pub struct SealingKey(RandomizedNonceKey);

impl SealingKey {
    /// The key whose bytes are `key`.
    ///
    /// # Errors
    /// Preserves failures from the cryptographic provider.
    pub fn new(key: &Secret) -> Result<Self, CryptoError> {
        Ok(Self(RandomizedNonceKey::new(&AES_256_GCM, key.as_bytes())?))
    }

    /// The key HKDF-SHA256 derives from `secret` with `info` and no salt, which a
    /// secret of 256 random bits needs none of. Keys derived for different `info`
    /// are unrelated.
    ///
    /// # Errors
    /// Preserves failures from the cryptographic provider.
    pub fn derive(secret: &[u8], info: &[u8]) -> Result<Self, CryptoError> {
        let mut key = Zeroizing::new([0; 32]);
        Salt::new(HKDF_SHA256, &[])
            .extract(secret)
            .expand(&[info], &AES_256_GCM)?
            .fill(key.as_mut_slice())?;
        Ok(Self(RandomizedNonceKey::new(&AES_256_GCM, key.as_slice())?))
    }

    /// Encrypts `plaintext`, authenticating `aad` with it. The plaintext is
    /// copied only into a buffer with room for the tag, which is zeroized when
    /// dropped, so no copy of it outlives the call.
    ///
    /// # Errors
    /// Preserves failures from the random source and the cryptographic provider.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sealed =
            Zeroizing::new(Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len()));
        sealed.extend_from_slice(plaintext);
        let nonce = self
            .0
            .seal_in_place_append_tag(Aad::from(aad), &mut *sealed)?;
        Ok([nonce.as_ref().as_slice(), &sealed].concat())
    }

    /// Decrypts a value [`Self::seal`] made with the same key and `aad`. The
    /// plaintext, such as a private key or a session's tokens, is zeroized when
    /// dropped.
    ///
    /// # Errors
    /// Returns [`CryptoError::Unsealable`] for another key, other associated data
    /// or a modified value.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (nonce, rest) = sealed
            .split_at_checked(NONCE_LEN)
            .ok_or(CryptoError::Unsealable)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let mut opened = Zeroizing::new(rest.to_vec());
        // A failed tag check says nothing more than this variant does.
        let length = self
            .0
            .open_in_place(nonce, Aad::from(aad), &mut opened)
            .map_err(|_| CryptoError::Unsealable)?
            .len();
        opened.truncate(length);
        Ok(opened)
    }
}

impl fmt::Debug for SealingKey {
    /// Renders a safe diagnostic representation without exposing the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealingKey(REDACTED)")
    }
}

/// The key that seals signing keys in the database, from configuration, as a
/// [`SealingKey`]: the associated data binds each sealed key to its record.
pub struct KeyEncryptionKey(SealingKey);

impl KeyEncryptionKey {
    /// Parses the KEK from its configured text: 32 bytes in unpadded base64url.
    ///
    /// # Errors
    /// Rejects other encodings and lengths other than 32 bytes.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        SealingKey::new(&Secret::parse(text)?).map(Self)
    }

    /// Generates a KEK, for tests and development.
    ///
    /// # Errors
    /// Preserves failures from the random source.
    pub fn generate() -> Result<Self, CryptoError> {
        SealingKey::new(&Secret::generate()?).map(Self)
    }

    /// See [`SealingKey::seal`].
    ///
    /// # Errors
    /// Preserves failures from the random source and the cryptographic provider.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.seal(plaintext, aad)
    }

    /// See [`SealingKey::open`].
    ///
    /// # Errors
    /// Returns [`CryptoError::Unsealable`] for another KEK, other associated data or
    /// a modified value.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.0.open(sealed, aad)
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
