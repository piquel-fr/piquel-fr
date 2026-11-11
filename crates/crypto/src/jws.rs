//! The one RS256 verifier: what auth checks its own tokens with, and what every
//! SDK built on this crate checks auth's and other issuers' tokens with. A token
//! is split by [`Compact`], whose header each side reads under its own policy, and
//! verified by an [`Rs256VerifyingKey`], which judges a key as every SDK does.
//!
//! ```
//! use sourceorigin_crypto::{Compact, KeyDefect, Rs256VerifyingKey, VerifyError};
//!
//! let token = Compact::split("eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl")?;
//! assert_eq!(token.header(), br#"{"alg":"RS256"}"#);
//! // A 1024-bit modulus verifies nothing: the key is at fault, not the token.
//! let weak = Rs256VerifyingKey::new(&[0xc5; 128], &[1, 0, 1]);
//! assert!(matches!(weak.defect(), Some(KeyDefect::ModulusSize(1024))));
//! assert!(matches!(
//!     weak.verify(token.signing_input(), token.signature()),
//!     Err(VerifyError::Unusable(KeyDefect::ModulusSize(1024)))
//! ));
//! # Ok::<(), sourceorigin_crypto::Malformed>(())
//! ```

use aws_lc_rs::{
    error::KeyRejected,
    signature::{ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

/// Longest compact token read, in bytes: decoding is bounded before it starts.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Shortest RSA modulus a key may have, in bits (RFC 7518 §3.3).
const MIN_MODULUS_BITS: usize = 2048;
/// Longest RSA modulus a key may have, in bits, as aws-lc verifies.
const MAX_MODULUS_BITS: usize = 8192;
/// The only RSA exponent a key may have, big-endian: 65537. Cloudflare Workers imports
/// only 3, 17 and 65537, so a wider rule would let SDKs disagree on a key.
const EXPONENT: [u8; 3] = [1, 0, 1];

/// Why a compact token cannot be split, as a sentence for the caller's error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct Malformed(pub &'static str);

/// A compact JWS (RFC 7515 §7.1) split into its decoded parts. Nothing is
/// verified: read the header, verify the signature, and only then the payload.
#[derive(Clone)]
pub struct Compact<'a> {
    /// The decoded protected header, JSON as sent.
    header: Vec<u8>,
    /// `header.payload`, the bytes the signature covers.
    signing_input: &'a str,
    /// The decoded payload.
    payload: Vec<u8>,
    /// The decoded signature.
    signature: Vec<u8>,
}

impl<'a> Compact<'a> {
    /// Splits a token of at most [`MAX_TOKEN_BYTES`] into exactly three base64url
    /// segments and decodes them.
    ///
    /// # Errors
    /// [`Malformed`] for a longer token, another number of segments, or a segment
    /// that is not unpadded base64url.
    pub fn split(token: &'a str) -> Result<Self, Malformed> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Malformed("the token exceeds 16 KiB"));
        }
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(Malformed("the token is not three segments"));
        };
        let decode = |segment: &str| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .map_err(|_| Malformed("a segment is not base64url"))
        };
        Ok(Self {
            header: decode(header)?,
            signing_input: &token[..header.len() + 1 + payload.len()],
            payload: decode(payload)?,
            signature: decode(signature)?,
        })
    }

    /// The decoded protected header, for the caller to parse under its policy.
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// The bytes the signature covers.
    #[must_use]
    pub const fn signing_input(&self) -> &'a str {
        self.signing_input
    }

    /// The decoded payload. Read it only once the signature has been verified.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The decoded signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Why a signing key cannot verify signatures, as every SDK judges it.
#[derive(Clone, Debug, Error)]
pub enum KeyDefect {
    /// The RSA modulus, not counting leading zero bytes, is under 2048 or over 8192
    /// bits.
    #[error("its RSA modulus is {0} bits, outside 2048 to 8192")]
    ModulusSize(usize),
    /// The RSA exponent is not 65537, the one every SDK's runtime verifies with.
    #[error("its RSA exponent is not 65537")]
    Exponent,
    /// The cryptographic library refused the key.
    #[error("the cryptographic library refused it")]
    Rejected(#[source] KeyRejected),
}

/// A signature check failed.
#[derive(Clone, Debug, Error)]
pub enum VerifyError {
    /// The key cannot verify anything: whoever published it is at fault.
    #[error("the key cannot verify signatures")]
    Unusable(#[source] KeyDefect),
    /// The signature is not the key's over the signing input.
    #[error("the signature does not verify")]
    BadSignature,
}

/// An RSA public key, from its modulus and exponent, that verifies RS256
/// (RSASSA-PKCS1-v1_5 with SHA-256) signatures. Any modulus and exponent make
/// one; a key every SDK would refuse reports its [`KeyDefect`] instead of
/// verifying.
#[derive(Clone)]
pub struct Rs256VerifyingKey {
    /// The modulus and exponent, big-endian without leading zero bytes, so a padded
    /// key verifies as it does in every SDK.
    components: RsaPublicKeyComponents<Vec<u8>>,
    /// The key the library verifies with, or why it refused it. Parsed only for a
    /// key whose size and exponent are allowed.
    parsed: Result<ParsedPublicKey, KeyDefect>,
}

impl Rs256VerifyingKey {
    /// The key with modulus `n` and exponent `e`, big-endian bytes.
    #[must_use]
    pub fn new(n: &[u8], e: &[u8]) -> Self {
        let significant = |bytes: &[u8]| {
            let start = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len());
            bytes[start..].to_vec()
        };
        let components = RsaPublicKeyComponents {
            n: significant(n),
            e: significant(e),
        };
        let bits = components.n.first().map_or(0, |first| {
            components.n.len() * 8 - usize::try_from(first.leading_zeros()).unwrap_or(0)
        });
        let parsed = if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
            Err(KeyDefect::ModulusSize(bits))
        } else if components.e != EXPONENT {
            Err(KeyDefect::Exponent)
        } else {
            components
                .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
                .map_err(KeyDefect::Rejected)
        };
        Self { components, parsed }
    }

    /// The modulus, big-endian without leading zero bytes.
    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        &self.components.n
    }

    /// The exponent, big-endian without leading zero bytes.
    #[must_use]
    pub fn exponent(&self) -> &[u8] {
        &self.components.e
    }

    /// What keeps this key from verifying, if anything.
    #[must_use]
    pub fn defect(&self) -> Option<KeyDefect> {
        self.parsed.as_ref().err().cloned()
    }

    /// The key as a `SubjectPublicKeyInfo` in DER, if it can verify.
    #[must_use]
    pub fn der(&self) -> Option<&[u8]> {
        self.parsed.as_ref().ok().map(AsRef::as_ref)
    }

    /// Checks that `signature` is this key's RS256 signature of `signing_input`.
    ///
    /// # Errors
    /// [`VerifyError::Unusable`] for a key with a [`KeyDefect`], whatever the
    /// signature; [`VerifyError::BadSignature`] when the signature does not verify.
    pub fn verify(&self, signing_input: &str, signature: &[u8]) -> Result<(), VerifyError> {
        let key = self
            .parsed
            .as_ref()
            .map_err(|defect| VerifyError::Unusable(defect.clone()))?;
        key.verify_sig(signing_input.as_bytes(), signature)
            .map_err(|_| VerifyError::BadSignature)
    }
}
