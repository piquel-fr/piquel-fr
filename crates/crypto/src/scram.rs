use super::{CryptoError, Digest};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};
use rand::{RngCore, rngs::OsRng};
use std::fmt;

/// A SCRAM-SHA-256 verifier of a password (RFC 5802, RFC 7677): what a server
/// stores to check the password without knowing it. Displays in the RFC 5803 form
/// `PostgreSQL` accepts in place of a password,
/// `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, so a role's
/// password can be set without the server, or its logs, ever seeing it.
pub struct ScramVerifier {
    /// PBKDF2 iterations.
    iterations: u32,
    /// Random salt.
    salt: [u8; Self::SALT_BYTES],
    /// `SHA-256(HMAC(SaltedPassword, "Client Key"))`.
    stored_key: Digest,
    /// `HMAC(SaltedPassword, "Server Key")`.
    server_key: Digest,
}

impl ScramVerifier {
    /// `PostgreSQL`'s default iteration count and salt length.
    const ITERATIONS: u32 = 4096;
    /// Salt length in bytes.
    const SALT_BYTES: usize = 16;

    /// Derives a verifier of `password` with a fresh random salt. The password is
    /// used as given, as `SQLx`'s client does, not normalized with `SASLprep`; the
    /// two agree on ASCII passwords.
    ///
    /// # Errors
    /// Preserves failures from the random source and the cryptographic provider.
    pub fn new(password: &str) -> Result<Self, CryptoError> {
        let mut salt = [0; Self::SALT_BYTES];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(CryptoError::Random)?;
        Self::salted(password, salt, Self::ITERATIONS)
    }

    /// Derives the verifier of `password` with `salt`.
    fn salted(
        password: &str,
        salt: [u8; Self::SALT_BYTES],
        iterations: u32,
    ) -> Result<Self, CryptoError> {
        let mut salted = [0; Digest::LENGTH];
        pbkdf2_hmac(
            password.as_bytes(),
            &salt,
            iterations as usize,
            MessageDigest::sha256(),
            &mut salted,
        )?;
        let client_key = Digest::hmac(&salted, b"Client Key")?;
        Ok(Self {
            iterations,
            salt,
            stored_key: Digest::sha256(client_key.as_bytes()),
            server_key: Digest::hmac(&salted, b"Server Key")?,
        })
    }
}

impl fmt::Display for ScramVerifier {
    /// Writes the RFC 5803 form, in padded base64.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            STANDARD.encode(self.salt),
            STANDARD.encode(self.stored_key.as_bytes()),
            STANDARD.encode(self.server_key.as_bytes()),
        )
    }
}

#[cfg(test)]
impl ScramVerifier {
    /// The verifier of `password` with `salt` and `PostgreSQL`'s iteration count,
    /// to compare with one the server derived.
    pub(crate) fn with_salt(
        password: &str,
        salt: [u8; Self::SALT_BYTES],
    ) -> Result<Self, CryptoError> {
        Self::salted(password, salt, Self::ITERATIONS)
    }
}
