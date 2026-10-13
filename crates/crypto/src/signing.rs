//! RSA signing for interoperable `OpenID` Connect ID and access tokens.
use super::{
    CryptoError,
    jwt::{Algorithm, Claim, KeyType, KeyUse, TokenType},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;

/// RSA key size used by generated fixtures and exported test keys.
const GENERATED_RSA_BITS: u32 = 3_072;
/// Minimum RSA modulus size in bits.
const MIN_RSA_BITS: i32 = 2_048;
/// Maximum public key identifier length.
const MAX_KEY_ID_LENGTH: usize = 128;
/// Bounds allocation before decoding untrusted compact tokens.
const MAX_TOKEN_LENGTH: usize = 16_384;
/// Maximum tolerated future issuance time.
const ISSUED_AT_SKEW_SECONDS: i64 = 30;

/// Protected JOSE header. It is the only header this key writes and the only one it
/// accepts back: unknown fields, `crit` included, fail parsing.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header<'a> {
    /// Signing algorithm; any value other than RS256 fails parsing.
    alg: Algorithm,
    /// Key that signed the token.
    kid: Cow<'a, str>,
    /// Token type, which keeps ID and access tokens apart.
    typ: TokenType,
}

/// Public JSON Web Key Set published for this key. Fields are in sorted order, matching
/// the earlier `json!` output byte for byte.
#[derive(Serialize)]
struct JwkSet<'a> {
    /// The single signing key.
    keys: [Jwk<'a>; 1],
}

/// One public RSA signing key.
#[derive(Serialize)]
struct Jwk<'a> {
    /// Algorithm the key signs with.
    alg: Algorithm,
    /// Base64url RSA public exponent.
    e: String,
    /// Key identifier, matching the token header's `kid`.
    kid: &'a str,
    /// Key family.
    kty: KeyType,
    /// Base64url RSA modulus.
    n: String,
    /// Key purpose.
    #[serde(rename = "use")]
    key_use: KeyUse,
}

/// A configured RSA private key. Keep its stable key identifier with the PEM.
pub struct Rs256Key {
    /// Stable public key identifier.
    kid: String,
    /// Validated RSA private key.
    key: PKey<Private>,
    /// Public key set derived once from validated RSA material.
    public_keys: Value,
}

impl Rs256Key {
    /// Loads a PEM RSA private key and stable public key identifier.
    ///
    /// # Errors
    /// Returns an error for invalid PEM, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_pem(kid: impl Into<String>, pem: &str) -> Result<Self, CryptoError> {
        Self::from_key(kid.into(), PKey::private_key_from_pem(pem.as_bytes())?)
    }

    /// Generates a 3072-bit RSA key using the configured cryptographic provider.
    ///
    /// # Errors
    /// Preserves provider failures and rejects invalid key identifiers.
    pub fn generate(kid: impl Into<String>) -> Result<Self, CryptoError> {
        Self::from_key(
            kid.into(),
            PKey::from_rsa(Rsa::generate(GENERATED_RSA_BITS)?)?,
        )
    }

    /// Validates RSA size and key identifier for every construction path.
    fn from_key(kid: String, key: PKey<Private>) -> Result<Self, CryptoError> {
        let rsa = key.rsa()?;
        if rsa.n().num_bits() < MIN_RSA_BITS {
            return Err(CryptoError::RsaKeySize);
        }
        if kid.is_empty() || kid.len() > MAX_KEY_ID_LENGTH || kid.chars().any(char::is_whitespace) {
            return Err(CryptoError::KeyId);
        }
        let public_keys = serde_json::to_value(JwkSet {
            keys: [Jwk {
                alg: Algorithm::Rs256,
                e: URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
                kid: &kid,
                kty: KeyType::Rsa,
                n: URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
                key_use: KeyUse::Signature,
            }],
        })?;
        Ok(Self {
            kid,
            key,
            public_keys,
        })
    }

    /// Exports the private key as PEM for persistent key storage.
    ///
    /// # Errors
    /// Preserves encoding failures from the provider.
    pub fn private_key_pem(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.key.private_key_to_pem_pkcs8()?)
    }

    /// Exports the public key as PEM for independent verifiers.
    ///
    /// # Errors
    /// Preserves encoding failures from the provider.
    pub fn public_key_pem(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.key.public_key_to_pem()?)
    }

    /// Verifies headers, signature, issuer and issued-at time, allowing expired logout hints.
    fn verified(&self, token: &str, typ: TokenType, issuer: &str) -> Result<Value, CryptoError> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(CryptoError::InvalidToken);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(CryptoError::InvalidToken);
        }
        let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
        if header.typ != typ || header.kid != self.kid {
            return Err(CryptoError::InvalidToken);
        }
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.key)?;
        verifier.update(format!("{}.{}", parts[0], parts[1]).as_bytes())?;
        if !verifier.verify(&signature)? {
            return Err(CryptoError::Signature);
        }
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        if claims[Claim::Issuer.as_str()] != issuer
            || claims
                .get(Claim::IssuedAt.as_str())
                .and_then(Value::as_i64)
                .is_none_or(|iat| iat > Utc::now().timestamp() + ISSUED_AT_SKEW_SECONDS)
        {
            return Err(CryptoError::InvalidToken);
        }
        Ok(claims)
    }

    /// Signs JSON claims as a compact RS256 token whose `typ` header is `token_type`.
    ///
    /// # Errors
    /// Preserves provider and decoding failures; rejects invalid signatures or claims.
    pub fn sign(&self, token_type: TokenType, claims: &Value) -> Result<String, CryptoError> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header {
            alg: Algorithm::Rs256,
            kid: Cow::Borrowed(&self.kid),
            typ: token_type,
        })?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let input = format!("{header}.{payload}");
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        signer.update(input.as_bytes())?;
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?)
        ))
    }

    /// Returns the public key as a JSON Web Key Set.
    #[must_use]
    pub fn jwks(&self) -> Value {
        self.public_keys.clone()
    }

    /// Verifies a compact token, including its expiry.
    ///
    /// # Errors
    /// Preserves provider and decoding failures; rejects invalid signatures or claims.
    pub fn verify(
        &self,
        token: &str,
        token_type: TokenType,
        issuer: &str,
    ) -> Result<Value, CryptoError> {
        let claims = self.verified(token, token_type, issuer)?;
        if claims
            .get(Claim::ExpiresAt.as_str())
            .and_then(Value::as_i64)
            .is_none_or(|exp| exp <= Utc::now().timestamp())
        {
            return Err(CryptoError::Expired);
        }
        Ok(claims)
    }

    /// Verifies an ID token hint without requiring it to be unexpired.
    ///
    /// # Errors
    /// Preserves provider and decoding failures; rejects invalid signatures or claims.
    pub fn verify_id_token_hint(&self, token: &str, issuer: &str) -> Result<Value, CryptoError> {
        self.verified(token, TokenType::Id, issuer)
    }
}
#[cfg(test)]
mod tests {
    //! JWT policy, tampering and protected-header trust boundaries.
    use super::*;
    use serde_json::json;

    /// Signing enforces token types, signatures, issuer and expiry, while logout permits expired hints.
    #[test]
    fn rsa_verifies_signatures_types_expiry_and_logout_hints() {
        let key = Rs256Key::generate("test").expect("generate RSA test key");
        let now = Utc::now().timestamp();
        let claims = json!({"iss":"https://auth.example","sub":"user","aud":"client","iat":now-60,"exp":now-1});
        let expired = key
            .sign(TokenType::Id, &claims)
            .expect("sign expired ID token hint");
        assert!(
            key.verify(&expired, TokenType::Id, "https://auth.example")
                .is_err()
        );
        assert!(
            key.verify_id_token_hint(&expired, "https://auth.example")
                .is_ok()
        );
        assert!(
            key.verify_id_token_hint(&expired, "https://evil.example")
                .is_err()
        );
        let mut valid = claims;
        valid["exp"] = json!(now + 300);
        let token = key
            .sign(TokenType::Access, &valid)
            .expect("sign access token");
        assert!(
            key.verify(&token, TokenType::Access, "https://auth.example")
                .is_ok()
        );
        assert!(
            key.verify(&token, TokenType::Id, "https://auth.example")
                .is_err()
        );
        let mut bytes = token.into_bytes();
        let n = bytes.len();
        bytes[n - 10] = if bytes[n - 10] == b'A' { b'B' } else { b'A' };
        assert!(
            key.verify(
                std::str::from_utf8(&bytes).expect("modified compact token remains ASCII"),
                TokenType::Access,
                "https://auth.example"
            )
            .is_err()
        );
        assert_eq!(key.jwks()["keys"][0]["kty"], "RSA");
    }

    /// Even correctly RSA-signed inputs cannot choose an algorithm, type, key or critical extension.
    #[test]
    fn rejects_algorithm_confusion_and_unrecognized_headers() {
        let key = Rs256Key::generate("headers").expect("RSA key");
        let now = Utc::now().timestamp();
        let claims = json!({"iss":"https://auth.example", "iat":now, "exp":now+300});
        for (field, value) in [
            ("alg", json!("none")),
            ("alg", json!("HS256")),
            ("alg", json!("RS512")),
            ("typ", json!("at+jwt")),
            ("kid", json!("untrusted")),
            ("crit", json!([])),
            ("crit", json!(["b64"])),
        ] {
            let mut header = json!({"alg":Algorithm::Rs256.as_str(), "kid":key.kid, "typ":TokenType::Id.as_str()});
            header[field] = value;
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header")),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"))
            );
            // A valid RSA signature isolates header-policy rejection from signature failure.
            let mut signer = Signer::new(MessageDigest::sha256(), &key.key).expect("signer");
            signer.update(input.as_bytes()).expect("input");
            let token = format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("signature"))
            );
            assert!(
                matches!(
                    key.verify(&token, TokenType::Id, "https://auth.example"),
                    Err(CryptoError::InvalidToken | CryptoError::Json(_))
                ),
                "accepted {field}"
            );
        }
        // HMAC with public-key bytes is the classic asymmetric/symmetric algorithm confusion.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"headers","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        let input = format!("{header}.{payload}");
        let signature =
            crate::Digest::hmac(&key.public_key_pem().expect("public key"), input.as_bytes())
                .expect("HMAC")
                .encoded();
        let token = format!("{input}.{signature}");
        assert!(matches!(
            key.verify(&token, TokenType::Id, "https://auth.example"),
            Err(CryptoError::Json(_))
        ));
    }
}
