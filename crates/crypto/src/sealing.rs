//! AES-256-GCM sealing of private keys at rest under a key-encryption key (KEK).
use super::{CryptoError, Secret};
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use rand::{RngCore, rngs::OsRng};
use std::fmt;

/// Bytes of the random nonce that starts every sealed value.
const NONCE_BYTES: usize = 12;
/// Bytes of the authentication tag that ends every sealed value.
const TAG_BYTES: usize = 16;

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
        let mut nonce = [0; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(CryptoError::Random)?;
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            self.0.as_bytes(),
            Some(&nonce),
            aad,
            plaintext,
            &mut tag,
        )?;
        Ok([&nonce[..], &ciphertext, &tag].concat())
    }

    /// Decrypts a value [`Self::seal`] made with the same KEK and `aad`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Unsealable`] for another KEK, other associated data or
    /// a modified value.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < NONCE_BYTES + TAG_BYTES {
            return Err(CryptoError::Unsealable);
        }
        let (nonce, rest) = sealed.split_at(NONCE_BYTES);
        let (ciphertext, tag) = rest.split_at(rest.len() - TAG_BYTES);
        // OpenSSL reports a failed tag check as an empty error stack, which says
        // nothing more than this variant does.
        decrypt_aead(
            Cipher::aes_256_gcm(),
            self.0.as_bytes(),
            Some(nonce),
            aad,
            ciphertext,
            tag,
        )
        .map_err(|_| CryptoError::Unsealable)
    }
}

impl fmt::Debug for KeyEncryptionKey {
    /// Renders a safe diagnostic representation without exposing the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyEncryptionKey(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    //! Sealed values open only with their own KEK and associated data.
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    /// A sealed value fails to open with another KEK, swapped associated data or
    /// any modified byte, and parsing accepts only 32 bytes of unpadded base64url.
    #[test]
    fn sealed_values_open_only_with_their_key_and_associated_data() {
        let kek = KeyEncryptionKey::generate().expect("KEK");
        let sealed = kek.seal(b"private key", b"kid-1rsa").expect("seal");
        assert_eq!(
            kek.open(&sealed, b"kid-1rsa").expect("open"),
            b"private key"
        );
        let other = KeyEncryptionKey::generate().expect("other KEK");
        assert!(matches!(
            other.open(&sealed, b"kid-1rsa"),
            Err(CryptoError::Unsealable)
        ));
        assert!(matches!(
            kek.open(&sealed, b"kid-2rsa"),
            Err(CryptoError::Unsealable)
        ));
        for index in [0, NONCE_BYTES, sealed.len() - 1] {
            let mut modified = sealed.clone();
            modified[index] ^= 1;
            assert!(kek.open(&modified, b"kid-1rsa").is_err(), "byte {index}");
        }
        assert!(kek.open(&sealed[..TAG_BYTES], b"kid-1rsa").is_err());

        let encoded = Secret::generate().expect("secret").encoded();
        assert!(KeyEncryptionKey::parse(&encoded).is_ok());
        assert!(KeyEncryptionKey::parse(&format!("{encoded}\n")).is_ok());
        for invalid in [format!("{encoded}="), "not base64!".to_owned()] {
            assert!(matches!(
                KeyEncryptionKey::parse(&invalid),
                Err(CryptoError::Encoding(_))
            ));
        }
        for bytes in [&[0; 31][..], &[0; 33]] {
            assert!(matches!(
                KeyEncryptionKey::parse(&URL_SAFE_NO_PAD.encode(bytes)),
                Err(CryptoError::SecretLength)
            ));
        }
        assert_eq!(format!("{kek:?}"), "KeyEncryptionKey(REDACTED)");
    }
}
