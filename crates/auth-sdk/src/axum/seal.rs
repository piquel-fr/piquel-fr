//! Sealing: AES-256-GCM under keys derived with HKDF-SHA256 from the app's
//! [`CookieKey`], for the session and pending-login cookies the browser keeps.

use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD},
    },
};
use serde::{Serialize, de::DeserializeOwned};
use sourceorigin_crypto::{CryptoError, Secret};
use std::fmt;

/// Bytes in a cookie key, and in the AES-256 keys derived from it.
const SECRET_BYTES: usize = 32;

/// How a cookie key may be written: `openssl rand -base64 32` prints padded
/// standard base64, and piqueld generates secrets as hex or unpadded base64url.
/// No key reads two ways: hex of 32 bytes is longer than their base64, and text
/// valid in both base64 alphabets decodes to the same bytes in each.
#[derive(Clone, Copy)]
enum Encoding {
    /// Hexadecimal, in either case.
    Hex,
    /// Standard base64, padded or not.
    Base64,
    /// URL-safe base64, padded or not.
    Base64Url,
}

impl Encoding {
    /// Every encoding, in the order a key is tried in: hex first, since hex text is
    /// also base64.
    const ALL: [Self; 3] = [Self::Hex, Self::Base64, Self::Base64Url];

    /// Base64 with optional padding, refusing stray trailing bits.
    const PADDING_OPTIONAL: GeneralPurposeConfig =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);

    /// The bytes `text` holds in this encoding, if it is written in it.
    fn decode(self, text: &str) -> Option<Vec<u8>> {
        let base64 = |alphabet| {
            GeneralPurpose::new(alphabet, Self::PADDING_OPTIONAL)
                .decode(text)
                .ok()
        };
        match self {
            Self::Hex => {
                let (pairs, odd) = text.as_bytes().as_chunks::<2>();
                if !odd.is_empty() {
                    return None;
                }
                pairs
                    .iter()
                    .map(|pair| {
                        let [high, low] = pair.map(|digit| char::from(digit).to_digit(16));
                        u8::try_from(high? << 4 | low?).ok()
                    })
                    .collect()
            }
            Self::Base64 => base64(&alphabet::STANDARD),
            Self::Base64Url => base64(&alphabet::URL_SAFE),
        }
    }
}

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
    Crypto(#[from] CryptoError),
    /// The value did not serialize.
    #[error("the sealed value did not serialize")]
    Encode(#[from] serde_json::Error),
}

/// The crypto crate's AES-256-GCM key for one purpose, with a random nonce per seal.
/// Its output binds a context, the cookie's client and name, so a value sealed under
/// one name does not open under another.
pub(super) struct SealingKey(sourceorigin_crypto::SealingKey);

impl SealingKey {
    /// The key for `purpose` derived from `secret`, which holds 256 random bits.
    fn derive(secret: &[u8], purpose: Purpose) -> Result<Self, CryptoError> {
        sourceorigin_crypto::SealingKey::derive(secret, purpose.info()).map(Self)
    }

    /// `value` as JSON, sealed for `context`: base64url of the nonce, the ciphertext
    /// and the tag.
    pub(super) fn seal(&self, value: &impl Serialize, context: &str) -> Result<String, SealError> {
        let sealed = self
            .0
            .seal(&serde_json::to_vec(value)?, context.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// The value sealed for `context`, if `sealed` opens with this key and parses.
    /// Anything else, tampered with, sealed for another context or by another key, is
    /// `None`.
    pub(super) fn open<T: DeserializeOwned>(&self, sealed: &str, context: &str) -> Option<T> {
        let sealed = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let plain = self.0.open(&sealed, context.as_bytes()).ok()?;
        serde_json::from_slice(&plain).ok()
    }
}

/// The secret sealing the cookies the browser keeps: the session, with the user's
/// tokens, and each login waiting at auth, with its PKCE verifier and `nonce`. Every
/// replica needs the same key: keep it like any other secret, and generate it with
/// `openssl rand -base64 32`, or as a 32-byte secret piqueld generates. Changing it
/// signs every user out, but ends no grant at auth: if the key leaked, rotate the
/// client secret too, with no grace period, since the refresh tokens in captured
/// cookies stay valid without it.
///
/// ```
/// use sourceorigin_auth::axum::CookieKey;
///
/// let key = CookieKey::parse("q5xP0Pl8m0l3pkk1Hk0aQe9H6P7l4H6Jt6bq0c5u3jE=")?;
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
    /// The text is neither base64, base64url nor hex.
    #[error("a cookie key must be 32 bytes in base64, base64url or hex")]
    Unrecognized,
    /// The key does not hold 32 bytes.
    #[error("a cookie key must hold 32 bytes, not {0}")]
    WrongLength(usize),
    /// The operating system could not supply random bytes.
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] CryptoError),
    /// The keys could not be derived.
    #[error("the cookie key could not be derived")]
    Crypto(#[source] CryptoError),
}

impl CookieKey {
    /// The key `text` holds: 32 bytes in standard base64, as
    /// `openssl rand -base64 32` prints, in base64url or in hex, as piqueld generates
    /// them. Base64 may be padded or not, and surrounding ASCII whitespace is
    /// ignored.
    ///
    /// # Errors
    /// [`CookieKeyError::WrongLength`] if the text holds other than 32 bytes, or
    /// [`CookieKeyError::Unrecognized`] if it is in none of these encodings.
    pub fn parse(text: &str) -> Result<Self, CookieKeyError> {
        let text = text.trim_ascii();
        let decoded: Vec<Vec<u8>> = Encoding::ALL
            .iter()
            .filter_map(|encoding| encoding.decode(text))
            .collect();
        match decoded.iter().find(|bytes| bytes.len() == SECRET_BYTES) {
            Some(secret) => Self::from_secret(secret),
            None => Err(decoded
                .first()
                .map_or(CookieKeyError::Unrecognized, |bytes| {
                    CookieKeyError::WrongLength(bytes.len())
                })),
        }
    }

    /// A random key, for development and tests: it lives in this process only, so
    /// other replicas cannot open its cookies, and a restart signs every user out.
    ///
    /// # Errors
    /// [`CookieKeyError::Randomness`] if the operating system cannot supply random
    /// bytes.
    pub fn generate() -> Result<Self, CookieKeyError> {
        let secret = Secret::generate().map_err(CookieKeyError::Randomness)?;
        Self::from_secret(secret.as_bytes())
    }

    /// The keys derived from `secret`.
    pub(super) fn from_secret(secret: &[u8]) -> Result<Self, CookieKeyError> {
        let derive = |purpose| SealingKey::derive(secret, purpose).map_err(CookieKeyError::Crypto);
        Ok(Self {
            session: derive(Purpose::Session)?,
            pending: derive(Purpose::PendingLogin)?,
        })
    }
}
