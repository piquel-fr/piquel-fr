//! Exact ES256 compact-JWS signing used by authentication token categories.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
    pkcs8::DecodePrivateKey,
};
#[cfg(test)]
use rand::rngs::OsRng;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

/// Local PEM-backed ES256 signing provider.
pub struct Es256KeyProvider {
    kid: String,
    signing: SigningKey,
}

impl Es256KeyProvider {
    /// Loads a P-256 PKCS#8 PEM signing key.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM is not a P-256 PKCS#8 private key.
    #[allow(clippy::result_unit_err)]
    pub fn from_pkcs8_pem(kid: impl Into<String>, pem: &str) -> Result<Self, ()> {
        let kid = kid.into();
        if kid.is_empty() || kid.len() > 128 || kid.chars().any(char::is_whitespace) {
            return Err(());
        }
        Ok(Self {
            kid,
            signing: SigningKey::from_pkcs8_pem(pem).map_err(|_| ())?,
        })
    }

    /// Generates an ephemeral key for tests only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn generate_for_tests(kid: impl Into<String>) -> Self {
        Self {
            kid: kid.into(),
            signing: SigningKey::random(&mut OsRng),
        }
    }

    pub(crate) fn sign<T: Serialize>(&self, token_type: &str, claims: &T) -> Result<String, ()> {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "ES256",
                "kid": self.kid,
                "typ": token_type,
            }))
            .map_err(|_| ())?,
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| ())?);
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    pub(crate) fn verify<T: DeserializeOwned>(
        &self,
        token_type: &str,
        token: &str,
    ) -> Result<T, ()> {
        if token.len() > 8192 {
            return Err(());
        }
        let mut pieces = token.split('.');
        let header_part = pieces.next().ok_or(())?;
        let claims_part = pieces.next().ok_or(())?;
        let signature_part = pieces.next().ok_or(())?;
        if pieces.next().is_some() {
            return Err(());
        }
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_part).map_err(|_| ())?)
                .map_err(|_| ())?;
        if header.get("alg") != Some(&json!("ES256"))
            || header.get("kid") != Some(&json!(self.kid))
            || header.get("typ") != Some(&json!(token_type))
        {
            return Err(());
        }
        let signature = URL_SAFE_NO_PAD.decode(signature_part).map_err(|_| ())?;
        let signature = Signature::from_slice(&signature).map_err(|_| ())?;
        self.signing
            .verifying_key()
            .verify(
                format!("{header_part}.{claims_part}").as_bytes(),
                &signature,
            )
            .map_err(|_| ())?;
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_part).map_err(|_| ())?)
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    #[test]
    fn token_type_and_signature_are_enforced() {
        let keys = Es256KeyProvider::generate_for_tests("test-key");
        let token = keys
            .sign("purpose+jwt", &json!({"subject":"user"}))
            .expect("sign token");
        assert_eq!(
            keys.verify::<serde_json::Value>("purpose+jwt", &token),
            Ok(json!({"subject":"user"}))
        );
        assert!(keys.verify::<serde_json::Value>("at+jwt", &token).is_err());

        let mut tampered = token.into_bytes();
        let last = tampered.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(
            keys.verify::<serde_json::Value>(
                "purpose+jwt",
                std::str::from_utf8(&tampered).expect("ASCII token")
            )
            .is_err()
        );
    }

    #[test]
    fn pkcs8_pem_loading_uses_the_signing_path() {
        let signing = SigningKey::random(&mut OsRng);
        let pem = signing.to_pkcs8_pem(LineEnding::LF).expect("PKCS#8 PEM");
        let keys = Es256KeyProvider::from_pkcs8_pem("configured-key", pem.as_str())
            .expect("configured signing key");
        let token = keys
            .sign("purpose+jwt", &json!({"configured":true}))
            .expect("sign with configured key");
        assert_eq!(
            keys.verify::<serde_json::Value>("purpose+jwt", &token),
            Ok(json!({"configured":true}))
        );
    }
}
