//! Sealing: AES-256-GCM under keys derived with HKDF-SHA256 from the app's
//! [`CookieKey`], for the session and pending-login cookies the browser keeps.

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey},
    error::Unspecified,
    hkdf::{HKDF_SHA256, Salt},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;

/// Bytes in a cookie key, and in the AES-256 keys derived from it.
const SECRET_BYTES: usize = 32;

/// What a sealing key is for, so the keys derived from one secret for two purposes
/// are unrelated. Each is the HKDF `info`, which names the format version: a new
/// format gets a new `info`, so cookies of the old one no longer open.
#[derive(Clone, Copy)]
enum Purpose {
    /// A signed-in session.
    Session,
    /// A login waiting for its callback.
    PendingLogin,
}

impl Purpose {
    /// The HKDF `info`. Every SDK uses the same, so their cookies interoperate.
    const fn info(self) -> &'static [u8] {
        match self {
            Self::Session => b"sourceorigin-auth session v1",
            Self::PendingLogin => b"sourceorigin-auth pending login v1",
        }
    }
}

/// Sealing could not run: the AEAD failed, or the value did not serialize.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError {
    /// AES-GCM refused, which only invalid lengths cause.
    #[error("sealing failed")]
    Crypto(#[from] Unspecified),
    /// The value did not serialize.
    #[error("the sealed value did not serialize")]
    Encode(#[from] serde_json::Error),
}

/// An AES-256-GCM key for one purpose, with a random nonce per seal. Its output binds
/// a context, the cookie's client and name, so a value sealed under one name does not
/// open under another.
pub(super) struct SealingKey(RandomizedNonceKey);

impl SealingKey {
    /// The key for `purpose` derived from `secret`, which holds 256 random bits: HKDF
    /// needs no salt then.
    fn derive(secret: &[u8], purpose: Purpose) -> Result<Self, Unspecified> {
        let mut key = [0; SECRET_BYTES];
        Salt::new(HKDF_SHA256, &[])
            .extract(secret)
            .expand(&[purpose.info()], &AES_256_GCM)?
            .fill(&mut key)?;
        Ok(Self(RandomizedNonceKey::new(&AES_256_GCM, &key)?))
    }

    /// `value` as JSON, sealed for `context`: base64url of the nonce, the ciphertext
    /// and the tag.
    pub(super) fn seal(&self, value: &impl Serialize, context: &str) -> Result<String, SealError> {
        let mut sealed = serde_json::to_vec(value)?;
        let nonce = self
            .0
            .seal_in_place_append_tag(Aad::from(context.as_bytes()), &mut sealed)?;
        let mut framed = nonce.as_ref().to_vec();
        framed.append(&mut sealed);
        Ok(URL_SAFE_NO_PAD.encode(framed))
    }

    /// The value sealed for `context`, if `sealed` opens with this key and parses.
    /// Anything else, tampered with, sealed for another context or by another key, is
    /// `None`.
    pub(super) fn open<T: DeserializeOwned>(&self, sealed: &str, context: &str) -> Option<T> {
        let framed = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let (nonce, sealed) = framed.split_at_checked(NONCE_LEN)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut sealed = sealed.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(context.as_bytes()), &mut sealed)
            .ok()?;
        serde_json::from_slice(plain).ok()
    }
}

/// The secret sealing the cookies the browser keeps: the session, with the user's
/// tokens, and each login waiting at auth, with its PKCE verifier and `nonce`. Every
/// replica needs the same key: keep it like any other secret, and generate it with
/// `openssl rand -base64 32`. Changing it signs every user out, but ends no grant at
/// auth: if the key leaked, rotate the client secret too, with no grace period, since
/// the refresh tokens in captured cookies stay valid without it.
///
/// ```
/// use sourceorigin_auth::axum::CookieKey;
///
/// let key = CookieKey::from_base64("q5xP0Pl8m0l3pkk1Hk0aQe9H6P7l4H6Jt6bq0c5u3jE=")?;
/// // Keys are never printed.
/// assert_eq!(format!("{key:?}"), "CookieKey(REDACTED)");
/// # Ok::<(), sourceorigin_auth::axum::CookieKeyError>(())
/// ```
pub struct CookieKey {
    /// Seals sessions.
    pub(super) session: SealingKey,
    /// Seals pending logins.
    pub(super) pending: SealingKey,
}

impl fmt::Debug for CookieKey {
    /// Never prints the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieKey(REDACTED)")
    }
}

/// A [`CookieKey`] could not be made.
#[derive(Debug, thiserror::Error)]
pub enum CookieKeyError {
    /// The text is not standard base64.
    #[error("a cookie key must be standard base64, as `openssl rand -base64 32` prints")]
    NotBase64(#[source] base64::DecodeError),
    /// The key does not hold 32 bytes.
    #[error("a cookie key must hold 32 bytes, not {0}")]
    WrongLength(usize),
    /// The operating system could not supply random bytes.
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] rand::Error),
    /// The keys could not be derived.
    #[error("the cookie key could not be derived")]
    Crypto(#[source] Unspecified),
}

impl CookieKey {
    /// The key `text` holds: 32 bytes in standard base64, surrounding whitespace
    /// ignored, as `openssl rand -base64 32` prints.
    ///
    /// # Errors
    /// [`CookieKeyError::NotBase64`] or [`CookieKeyError::WrongLength`].
    pub fn from_base64(text: &str) -> Result<Self, CookieKeyError> {
        let bytes = STANDARD
            .decode(text.trim())
            .map_err(CookieKeyError::NotBase64)?;
        if bytes.len() != SECRET_BYTES {
            return Err(CookieKeyError::WrongLength(bytes.len()));
        }
        Self::from_secret(&bytes)
    }

    /// A random key, for development and tests: it lives in this process only, so
    /// other replicas cannot open its cookies, and a restart signs every user out.
    ///
    /// # Errors
    /// [`CookieKeyError::Randomness`] if the operating system cannot supply random
    /// bytes.
    pub fn generate() -> Result<Self, CookieKeyError> {
        let mut bytes = [0; SECRET_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(CookieKeyError::Randomness)?;
        Self::from_secret(&bytes)
    }

    /// The keys derived from `secret`.
    fn from_secret(secret: &[u8]) -> Result<Self, CookieKeyError> {
        let derive = |purpose| SealingKey::derive(secret, purpose).map_err(CookieKeyError::Crypto);
        Ok(Self {
            session: derive(Purpose::Session)?,
            pending: derive(Purpose::PendingLogin)?,
        })
    }
}
