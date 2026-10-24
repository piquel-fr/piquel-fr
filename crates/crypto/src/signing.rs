//! RSA signing for interoperable `OpenID` Connect ID and access tokens, and the key
//! set that signs with one key and verifies with every key it publishes.
use super::CryptoError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use piquel_common::protocol::jwt::{
    Algorithm, Claim, Jwk, JwkSet, KeyId, KeyType, KeyUse, TokenType,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{borrow::Cow, collections::BTreeSet};

/// RSA key size used by generated keys.
const GENERATED_RSA_BITS: u32 = 3_072;
/// Minimum RSA modulus size in bits.
const MIN_RSA_BITS: i32 = 2_048;
/// Bounds allocation before decoding untrusted compact tokens.
const MAX_TOKEN_LENGTH: usize = 16_384;
/// Maximum tolerated future issuance time.
const ISSUED_AT_SKEW_SECONDS: i64 = 30;

/// Protected JOSE header. It is the only header auth writes and the only one it
/// accepts back: unknown fields, `crit` included, fail parsing.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header<'a> {
    /// Signing algorithm; a value outside [`Algorithm`] fails parsing.
    alg: Algorithm,
    /// Key that signed the token.
    kid: Cow<'a, str>,
    /// Token type, which keeps ID and access tokens apart.
    typ: TokenType,
}

/// A compact JWT split into its parts, with its header parsed but nothing verified.
struct Compact<'a> {
    /// The parsed protected header.
    header: Header<'static>,
    /// `header.payload`, the bytes the signature covers.
    signing_input: &'a str,
    /// The base64url payload.
    payload: &'a str,
    /// The decoded signature.
    signature: Vec<u8>,
}

impl<'a> Compact<'a> {
    /// Splits a bounded token into exactly three parts and parses its header.
    fn parse(token: &'a str) -> Result<Self, CryptoError> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(CryptoError::InvalidToken);
        }
        let (signing_input, signature) = token.rsplit_once('.').ok_or(CryptoError::InvalidToken)?;
        let (header, payload) = signing_input
            .split_once('.')
            .filter(|(_, payload)| !payload.contains('.'))
            .ok_or(CryptoError::InvalidToken)?;
        Ok(Self {
            header: serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?,
            signing_input,
            payload,
            signature: URL_SAFE_NO_PAD.decode(signature)?,
        })
    }
}

/// A public signing key, as JWKS publishes it: what verifies the tokens it signed.
#[derive(Clone)]
pub struct PublicKey {
    /// The published form.
    jwk: Jwk,
    /// The validated key.
    key: PKey<Public>,
}

impl PublicKey {
    /// Builds the key a JWK describes.
    ///
    /// # Errors
    /// Rejects malformed or undersized keys and invalid key identifiers.
    pub fn from_jwk(jwk: Jwk) -> Result<Self, CryptoError> {
        jwk.kid.parse::<KeyId>().map_err(|_| CryptoError::KeyId)?;
        let key = match jwk.kty {
            KeyType::Rsa => {
                let component = |value: &str| -> Result<BigNum, CryptoError> {
                    Ok(BigNum::from_slice(&URL_SAFE_NO_PAD.decode(value)?)?)
                };
                let rsa = Rsa::from_public_components(component(&jwk.n)?, component(&jwk.e)?)?;
                if rsa.n().num_bits() < MIN_RSA_BITS {
                    return Err(CryptoError::RsaKeySize);
                }
                PKey::from_rsa(rsa)?
            }
        };
        Ok(Self { jwk, key })
    }

    /// The key identifier tokens name in their `kid` header.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.jwk.kid
    }

    /// The key as JWKS publishes it.
    #[must_use]
    pub const fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Whether this key signs with `alg`. Requiring the header's algorithm to be
    /// one of the key's own rules out algorithm confusion (RFC 8725 §3.1).
    const fn signs_with(&self, alg: Algorithm) -> bool {
        match (self.jwk.kty, alg) {
            (KeyType::Rsa, Algorithm::Rs256) => true,
        }
    }

    /// Verifies the signature, type, issuer and issue time of a token naming this
    /// key, but not its expiry, and returns its claims.
    fn verified(
        &self,
        token: &Compact<'_>,
        typ: TokenType,
        issuer: &str,
    ) -> Result<Value, CryptoError> {
        if token.header.typ != typ || !self.signs_with(token.header.alg) {
            return Err(CryptoError::InvalidToken);
        }
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.key)?;
        verifier.update(token.signing_input.as_bytes())?;
        if !verifier.verify(&token.signature)? {
            return Err(CryptoError::Signature);
        }
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.payload)?)?;
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
}

/// An RSA private key that signs RS256 tokens under its key identifier.
pub struct Rs256Key {
    /// Key identifier written in every token's header.
    kid: String,
    /// Validated RSA private key.
    key: PKey<Private>,
    /// The public half, derived once from the private key.
    public: PublicKey,
}

impl Rs256Key {
    /// Loads a PEM RSA private key under `kid`.
    ///
    /// # Errors
    /// Returns an error for invalid PEM, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_pem(kid: impl Into<String>, pem: &str) -> Result<Self, CryptoError> {
        Self::from_key(kid.into(), PKey::private_key_from_pem(pem.as_bytes())?)
    }

    /// Loads a PKCS#8 DER RSA private key under `kid`, as [`Self::private_key_der`] exports it.
    ///
    /// # Errors
    /// Returns an error for invalid DER, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, CryptoError> {
        Self::from_key(kid.into(), PKey::private_key_from_pkcs8(der)?)
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
        let public = PublicKey::from_jwk(Jwk {
            alg: Some(Algorithm::Rs256),
            e: URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
            kid: kid.clone(),
            kty: KeyType::Rsa,
            n: URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
            key_use: Some(KeyUse::Signature),
        })?;
        Ok(Self { kid, key, public })
    }

    /// The key identifier tokens name in their `kid` header.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public half, which verifies this key's tokens.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Exports the private key as PKCS#8 DER, for sealing in key storage.
    ///
    /// # Errors
    /// Preserves encoding failures from the provider.
    pub fn private_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.key.private_key_to_pkcs8()?)
    }

    /// Exports the private key as PEM, for test fixtures.
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

    /// Signs claims as a compact RS256 token whose `typ` header is `token_type`.
    ///
    /// # Errors
    /// Preserves provider and serialization failures.
    pub fn sign(
        &self,
        token_type: TokenType,
        claims: &impl Serialize,
    ) -> Result<String, CryptoError> {
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

    /// This key alone as a JSON Web Key Set, for fixtures that publish one key.
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public.jwk.clone()],
        }
    }
}

/// The keys auth signs and verifies with: one signing key, the published keys,
/// whose tokens verify and which JWKS lists, and retired keys, which verify only
/// `id_token_hint`s, since a hint may outlive its key's publication. Each key
/// identifier appears once, and a token is checked only against the key it names.
pub struct KeySet {
    /// The key that signs new tokens; one of `published`.
    signer: Rs256Key,
    /// Keys whose tokens verify, in JWKS order.
    published: Vec<PublicKey>,
    /// Keys that verify only `id_token_hint`s.
    retired: Vec<PublicKey>,
    /// The published keys as a JSON Web Key Set.
    jwks: JwkSet,
}

impl KeySet {
    /// Builds a set that signs with `signer`, which `published` must contain.
    ///
    /// # Errors
    /// Returns [`CryptoError::KeySet`] if `signer` is not published as itself, or a
    /// key identifier appears twice.
    pub fn new(
        signer: Rs256Key,
        published: Vec<PublicKey>,
        retired: Vec<PublicKey>,
    ) -> Result<Self, CryptoError> {
        let mut kids = BTreeSet::new();
        if !published.iter().any(|key| key.jwk == signer.public.jwk)
            || !published
                .iter()
                .chain(&retired)
                .all(|key| kids.insert(key.kid()))
        {
            return Err(CryptoError::KeySet);
        }
        let jwks = JwkSet {
            keys: published.iter().map(|key| key.jwk.clone()).collect(),
        };
        Ok(Self {
            signer,
            published,
            retired,
            jwks,
        })
    }

    /// A set of one key, which signs and alone verifies.
    #[must_use]
    pub fn single(signer: Rs256Key) -> Self {
        Self {
            published: vec![signer.public.clone()],
            retired: Vec::new(),
            jwks: signer.jwks(),
            signer,
        }
    }

    /// The key that signs new tokens.
    #[must_use]
    pub const fn signer(&self) -> &Rs256Key {
        &self.signer
    }

    /// Signs claims with the signing key; see [`Rs256Key::sign`].
    ///
    /// # Errors
    /// Preserves provider and serialization failures.
    pub fn sign(
        &self,
        token_type: TokenType,
        claims: &impl Serialize,
    ) -> Result<String, CryptoError> {
        self.signer.sign(token_type, claims)
    }

    /// The published keys as a JSON Web Key Set.
    #[must_use]
    pub const fn jwks(&self) -> &JwkSet {
        &self.jwks
    }

    /// Verifies a compact token signed by a published key, including its expiry,
    /// and decodes its claims as `T`.
    ///
    /// # Errors
    /// Returns [`CryptoError::UnknownKey`] for a key outside the published ones;
    /// otherwise preserves provider and decoding failures and rejects invalid
    /// signatures or claims.
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        token_type: TokenType,
        issuer: &str,
    ) -> Result<T, CryptoError> {
        let token = Compact::parse(token)?;
        let claims = Self::find(&self.published, &token)?.verified(&token, token_type, issuer)?;
        if claims
            .get(Claim::ExpiresAt.as_str())
            .and_then(Value::as_i64)
            .is_none_or(|exp| exp <= Utc::now().timestamp())
        {
            return Err(CryptoError::Expired);
        }
        Ok(serde_json::from_value(claims)?)
    }

    /// Verifies an ID token hint signed by a published or retired key, without
    /// requiring it to be unexpired.
    ///
    /// # Errors
    /// Returns [`CryptoError::UnknownKey`] for a key outside the set; otherwise
    /// preserves provider and decoding failures and rejects invalid signatures or claims.
    pub fn verify_id_token_hint(&self, token: &str, issuer: &str) -> Result<Value, CryptoError> {
        let token = Compact::parse(token)?;
        Self::find(&self.published, &token)
            .or_else(|_| Self::find(&self.retired, &token))?
            .verified(&token, TokenType::Id, issuer)
    }

    /// The key among `keys` that `token` names.
    fn find<'k>(keys: &'k [PublicKey], token: &Compact<'_>) -> Result<&'k PublicKey, CryptoError> {
        keys.iter()
            .find(|key| key.kid() == token.header.kid)
            .ok_or(CryptoError::UnknownKey)
    }
}

#[cfg(test)]
mod tests {
    //! JWT policy, tampering, protected-header trust boundaries and key selection.
    use super::*;
    use serde_json::json;

    /// Signing enforces token types, signatures, issuer and expiry, while logout permits expired hints.
    #[test]
    fn rsa_verifies_signatures_types_expiry_and_logout_hints() {
        let keys = KeySet::single(Rs256Key::generate("test").expect("generate RSA test key"));
        let now = Utc::now().timestamp();
        let claims = json!({"iss":"https://auth.example","sub":"user","aud":"client","iat":now-60,"exp":now-1});
        let expired = keys
            .sign(TokenType::Id, &claims)
            .expect("sign expired ID token hint");
        assert!(
            keys.verify::<Value>(&expired, TokenType::Id, "https://auth.example")
                .is_err()
        );
        assert!(
            keys.verify_id_token_hint(&expired, "https://auth.example")
                .is_ok()
        );
        assert!(
            keys.verify_id_token_hint(&expired, "https://evil.example")
                .is_err()
        );
        let mut valid = claims;
        valid["exp"] = json!(now + 300);
        let token = keys
            .sign(TokenType::Access, &valid)
            .expect("sign access token");
        assert!(
            keys.verify::<Value>(&token, TokenType::Access, "https://auth.example")
                .is_ok()
        );
        assert!(
            keys.verify::<Value>(&token, TokenType::Id, "https://auth.example")
                .is_err()
        );
        let mut bytes = token.into_bytes();
        let n = bytes.len();
        bytes[n - 10] = if bytes[n - 10] == b'A' { b'B' } else { b'A' };
        assert!(
            keys.verify::<Value>(
                std::str::from_utf8(&bytes).expect("modified compact token remains ASCII"),
                TokenType::Access,
                "https://auth.example"
            )
            .is_err()
        );
        assert_eq!(keys.jwks().keys[0].kty, KeyType::Rsa);
    }

    /// Even correctly RSA-signed inputs cannot choose an algorithm, type, key or critical extension.
    #[test]
    fn rejects_algorithm_confusion_and_unrecognized_headers() {
        let keys = KeySet::single(Rs256Key::generate("headers").expect("RSA key"));
        let key = keys.signer();
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
                    keys.verify::<Value>(&token, TokenType::Id, "https://auth.example"),
                    Err(CryptoError::InvalidToken | CryptoError::UnknownKey | CryptoError::Json(_))
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
            keys.verify::<Value>(&token, TokenType::Id, "https://auth.example"),
            Err(CryptoError::Json(_))
        ));
    }

    /// During a rotation, tokens of every published key verify and JWKS lists them;
    /// a retired key verifies only ID token hints, and a key outside the set nothing.
    #[test]
    fn key_set_verifies_by_kid_and_limits_retired_keys_to_hints() {
        let [retiring, active, retired, unknown] = ["retiring", "active", "retired", "unknown"]
            .map(|kid| Rs256Key::generate(kid).expect("key"));
        let now = Utc::now().timestamp();
        let claims =
            json!({"iss":"https://auth.example", "aud":"client", "iat":now, "exp":now+300});
        let [by_retiring, by_retired, by_unknown] = [&retiring, &retired, &unknown]
            .map(|key| key.sign(TokenType::Id, &claims).expect("sign"));
        // A signer must be published, or verifiers could not check its tokens.
        assert!(matches!(
            KeySet::new(unknown, vec![retiring.public_key().clone()], vec![]),
            Err(CryptoError::KeySet)
        ));
        let published = vec![retiring.public_key().clone(), active.public_key().clone()];
        let keys =
            KeySet::new(active, published, vec![retired.public_key().clone()]).expect("key set");
        let by_active = keys.sign(TokenType::Id, &claims).expect("sign");
        for token in [&by_active, &by_retiring] {
            assert!(
                keys.verify::<Value>(token, TokenType::Id, "https://auth.example")
                    .is_ok()
            );
            assert!(
                keys.verify_id_token_hint(token, "https://auth.example")
                    .is_ok()
            );
        }
        assert!(matches!(
            keys.verify::<Value>(&by_retired, TokenType::Id, "https://auth.example"),
            Err(CryptoError::UnknownKey)
        ));
        assert!(
            keys.verify_id_token_hint(&by_retired, "https://auth.example")
                .is_ok()
        );
        assert!(matches!(
            keys.verify_id_token_hint(&by_unknown, "https://auth.example"),
            Err(CryptoError::UnknownKey)
        ));
        let kids: Vec<_> = keys
            .jwks()
            .keys
            .iter()
            .map(|key| key.kid.as_str())
            .collect();
        assert_eq!(kids, ["retiring", "active"]);

        // A repeated key identifier, even between published and retired keys, is refused.
        let signer = Rs256Key::generate("same").expect("key");
        let twin = Rs256Key::generate("same").expect("key");
        let published = vec![signer.public_key().clone()];
        assert!(matches!(
            KeySet::new(signer, published, vec![twin.public_key().clone()]),
            Err(CryptoError::KeySet)
        ));
    }
}
