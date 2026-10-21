//! Auditable cryptographic primitives for authentication; no browser or database policy.
/// RSA signing and verification of compact JWTs.
mod signing;
pub use signing::Rs256Key;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};
use std::fmt;
use thiserror::Error;

/// Byte length of 256-bit secrets and SHA-256 results.
const SECRET_BYTES: usize = 32;
/// Starts every generated client secret, so secret scanners can recognize leaked ones.
const CLIENT_SECRET_PREFIX: &str = "pqcs_";
/// RFC 7636 minimum verifier length.
const MIN_PKCE_VERIFIER_LENGTH: usize = 43;
/// RFC 7636 maximum verifier length.
const MAX_PKCE_VERIFIER_LENGTH: usize = 128;

/// Cryptographic failures, preserving provider diagnostics without secret values.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The operating system could not supply random bytes.
    #[error("operating system randomness unavailable")]
    Random(#[source] rand::Error),
    /// The cryptographic provider failed.
    #[error("cryptographic provider failed")]
    Provider(#[from] openssl::error::ErrorStack),
    /// A base64url value is malformed.
    #[error("invalid unpadded base64url encoding")]
    Encoding(#[from] base64::DecodeError),
    /// A decoded secret has the wrong size.
    #[error("secret must contain exactly 32 bytes")]
    SecretLength,
    /// An RSA key is too small.
    #[error("RSA signing key must contain at least 2048 bits")]
    RsaKeySize,
    /// The key identifier cannot safely appear in JWT headers.
    #[error("signing key ID must contain 1 to 128 characters without whitespace")]
    KeyId,
    /// A JWT segment contains malformed JSON.
    #[error("invalid JWT JSON")]
    Json(#[from] serde_json::Error),
    /// A token has invalid framing, headers or claims.
    #[error("JWT framing, headers or claims are invalid")]
    InvalidToken,
    /// A JWT signature did not verify.
    #[error("JWT signature is invalid")]
    Signature,
    /// A JWT has expired.
    #[error("JWT has expired")]
    Expired,
    /// The PKCE verifier violates RFC 7636.
    #[error("PKCE verifier must contain 43 to 128 unreserved ASCII characters")]
    PkceVerifier,
    /// The PKCE verifier does not match its challenge.
    #[error("PKCE S256 challenge does not match the verifier")]
    PkceMismatch,
}

/// A random 256-bit secret with redacted diagnostics.
#[derive(Clone)]
pub struct Secret([u8; SECRET_BYTES]);
impl Secret {
    /// Generates a secret using operating system randomness.
    ///
    /// # Errors
    /// Preserves failures from the random source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0; SECRET_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(CryptoError::Random)?;
        Ok(Self(bytes))
    }
    /// Derives a domain-separated secret key with HMAC-SHA256.
    ///
    /// # Errors
    /// Preserves failures from the cryptographic provider.
    pub fn derive(key: &[u8], context: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(Digest::hmac(key, context)?.0))
    }
    /// Parses a canonical, unpadded base64url secret.
    ///
    /// # Errors
    /// Rejects invalid encoding and lengths other than 32 bytes.
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let bytes = URL_SAFE_NO_PAD.decode(value)?;
        // Conversion returns the original secret bytes on failure, not a safe error source.
        Ok(Self(
            bytes.try_into().map_err(|_| CryptoError::SecretLength)?,
        ))
    }
    /// Exposes bytes only when required by a cryptographic operation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }
    /// Encodes the secret for transport.
    #[must_use]
    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
    /// Hashes the secret for storage.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::sha256(&self.0)
    }
}
impl fmt::Debug for Secret {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(REDACTED)")
    }
}

/// A SHA-256 digest or HMAC result, always exactly 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest([u8; SECRET_BYTES]);
impl Digest {
    /// Byte length of every digest.
    pub const LENGTH: usize = SECRET_BYTES;
    /// Computes SHA-256 over arbitrary bytes.
    #[must_use]
    pub fn sha256(value: &[u8]) -> Self {
        Self(Sha256::digest(value).into())
    }
    /// Computes HMAC-SHA256 using the supplied key.
    ///
    /// # Errors
    /// Preserves cryptographic provider failures.
    pub fn hmac(key: &[u8], value: &[u8]) -> Result<Self, CryptoError> {
        let key = PKey::hmac(key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(value)?;
        // HMAC-SHA256 always writes exactly 32 bytes; OpenSSL rejects a smaller buffer.
        let mut bytes = [0; SECRET_BYTES];
        signer.sign(&mut bytes)?;
        Ok(Self(bytes))
    }
    /// Exposes the digest for persistence or comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }
    /// Encodes the digest with unpadded base64url.
    #[must_use]
    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
    /// Compares equal-length byte strings in constant time; length is public.
    #[must_use]
    pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len() && openssl::memcmp::eq(left, right)
    }
}

/// A confidential OIDC client's secret: `pqcs_` followed by 256 random bits in
/// unpadded base64url. It is shown once; only its digest is stored.
///
/// SHA-256 suffices for the digest, rather than a slow password hash: a 256-bit
/// random value cannot be guessed, so slowing each guess down adds nothing but
/// latency to every token request.
pub struct ClientSecret(String);
impl ClientSecret {
    /// Generates a secret using operating system randomness.
    ///
    /// # Errors
    /// Preserves failures from the random source.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(format!(
            "{CLIENT_SECRET_PREFIX}{}",
            Secret::generate()?.encoded()
        )))
    }
    /// The secret, to show the operator once.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// The digest stored for this secret.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Self::digest_presented(&self.0)
    }
    /// The digest of a secret a client presents, to compare with stored digests.
    /// Secrets that predate the prefix are hashed the same way, so they keep working.
    #[must_use]
    pub fn digest_presented(secret: &str) -> Digest {
        Digest::sha256(secret.as_bytes())
    }
}
impl fmt::Debug for ClientSecret {
    /// Renders a safe diagnostic representation without exposing the secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientSecret(REDACTED)")
    }
}

/// PKCE S256 (RFC 7636) operations, shared by the OIDC provider and the social-login client.
pub struct Pkce;
impl Pkce {
    /// Computes an S256 challenge from a validated verifier.
    ///
    /// # Errors
    /// Rejects invalid verifier length or characters.
    pub fn challenge(verifier: &str) -> Result<String, CryptoError> {
        if !(MIN_PKCE_VERIFIER_LENGTH..=MAX_PKCE_VERIFIER_LENGTH).contains(&verifier.len())
            || !verifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return Err(CryptoError::PkceVerifier);
        }
        Ok(Digest::sha256(verifier.as_bytes()).encoded())
    }
    /// Checks whether a verifier matches an S256 challenge.
    ///
    /// # Errors
    /// Reports invalid verifier syntax or a mismatch.
    pub fn verify(verifier: &str, challenge: &str) -> Result<(), CryptoError> {
        if Digest::constant_time_eq(Self::challenge(verifier)?.as_bytes(), challenge.as_bytes()) {
            Ok(())
        } else {
            Err(CryptoError::PkceMismatch)
        }
    }
    /// Checks that an incoming challenge encodes a SHA-256 result.
    #[must_use]
    pub fn valid_challenge(challenge: &str) -> bool {
        Secret::parse(challenge).is_ok()
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
