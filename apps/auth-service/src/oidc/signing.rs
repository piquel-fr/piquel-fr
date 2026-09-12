//! RSA signing for interoperable `OpenID` Connect ID and access tokens.
use super::Value;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use serde_json::json;

/// A configured RSA private key. Keep its stable key identifier with the PEM.
pub struct Rs256KeyProvider {
    kid: String,
    key: PKey<Private>,
}
impl Rs256KeyProvider {
    /// Loads a PEM RSA private key and stable public key identifier.
    ///
    /// # Errors
    /// Returns an error for invalid PEM, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_pem(kid: impl Into<String>, pem: &str) -> anyhow::Result<Self> {
        let key = PKey::private_key_from_pem(pem.as_bytes())?;
        anyhow::ensure!(
            key.rsa()?.size() >= 256,
            "OIDC RSA keys must be at least 2048 bits"
        );
        let kid = kid.into();
        anyhow::ensure!(
            !kid.is_empty() && kid.len() <= 128 && !kid.chars().any(char::is_whitespace),
            "Invalid signing key identifier"
        );
        Ok(Self { kid, key })
    }
    /// Generates an ephemeral key for explicit local development and tests.
    ///
    /// # Errors
    /// Returns an error when the cryptographic provider cannot generate or encode the key.
    pub fn generate_for_development(kid: impl Into<String>) -> anyhow::Result<Self> {
        let key = Rsa::generate(3072)?;
        let pem = String::from_utf8(key.private_key_to_pem()?)?;
        Self::from_pem(kid, &pem)
    }
    fn verified(&self, token: &str, typ: &str, issuer: &str) -> Result<Value, ()> {
        if token.len() > 16384 {
            return Err(());
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(());
        }
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| ())?)
                .map_err(|_| ())?;
        if header["alg"] != "RS256"
            || header["typ"] != typ
            || header["kid"] != self.kid
            || header.get("crit").is_some()
        {
            return Err(());
        }
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| ())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.key).map_err(|_| ())?;
        verifier
            .update(format!("{}.{}", parts[0], parts[1]).as_bytes())
            .map_err(|_| ())?;
        if !verifier.verify(&signature).map_err(|_| ())? {
            return Err(());
        }
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| ())?)
                .map_err(|_| ())?;
        if claims["iss"] != issuer
            || claims
                .get("iat")
                .and_then(Value::as_i64)
                .is_none_or(|iat| iat > Utc::now().timestamp() + 30)
        {
            return Err(());
        }
        Ok(claims)
    }
}
impl Rs256KeyProvider {
    pub(super) fn sign(&self, token_type: &str, claims: &Value) -> Result<String, ()> {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg":"RS256","kid":self.kid,"typ":token_type}))
                .map_err(|_| ())?,
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| ())?);
        let input = format!("{header}.{payload}");
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).map_err(|_| ())?;
        signer.update(input.as_bytes()).map_err(|_| ())?;
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec().map_err(|_| ())?)
        ))
    }
    pub(super) fn jwks(&self) -> Value {
        // Constructors verify that the private key is RSA.
        let rsa = self.key.rsa().expect("validated RSA key");
        json!({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":self.kid,"n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]})
    }
    pub(super) fn verify(&self, token: &str, token_type: &str, issuer: &str) -> Result<Value, ()> {
        let claims = self.verified(token, token_type, issuer)?;
        if claims
            .get("exp")
            .and_then(Value::as_i64)
            .is_none_or(|exp| exp <= Utc::now().timestamp())
        {
            return Err(());
        }
        Ok(claims)
    }
    pub(super) fn verify_logout(&self, token: &str, issuer: &str) -> Result<Value, ()> {
        self.verified(token, "JWT", issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rsa_verifies_signatures_types_expiry_and_logout_hints() {
        let key =
            Rs256KeyProvider::generate_for_development("test").expect("generate RSA test key");
        let now = Utc::now().timestamp();
        let claims = json!({"iss":"https://auth.example","sub":"user","aud":"client","iat":now-60,"exp":now-1});
        let expired = key
            .sign("JWT", &claims)
            .expect("sign expired ID token hint");
        assert!(key.verify(&expired, "JWT", "https://auth.example").is_err());
        assert!(key.verify_logout(&expired, "https://auth.example").is_ok());
        assert!(key.verify_logout(&expired, "https://evil.example").is_err());
        let mut valid = claims;
        valid["exp"] = json!(now + 300);
        let token = key.sign("at+jwt", &valid).expect("sign access token");
        assert!(key.verify(&token, "at+jwt", "https://auth.example").is_ok());
        assert!(key.verify(&token, "JWT", "https://auth.example").is_err());
        let mut bytes = token.into_bytes();
        let n = bytes.len();
        bytes[n - 10] = if bytes[n - 10] == b'A' { b'B' } else { b'A' };
        assert!(
            key.verify(
                std::str::from_utf8(&bytes).expect("modified compact token remains ASCII"),
                "at+jwt",
                "https://auth.example"
            )
            .is_err()
        );
        assert_eq!(key.jwks()["keys"][0]["kty"], "RSA");
    }
}
