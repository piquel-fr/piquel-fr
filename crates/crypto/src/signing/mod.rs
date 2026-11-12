//! RSA signing for interoperable `OpenID` Connect ID and access tokens, and the key
//! set that signs with one key and verifies with every key it publishes.
use super::{CryptoError, Digest};
use crate::{Compact, Rs256VerifyingKey, VerifyError};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rand::SystemRandom,
    rsa::KeySize,
    signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sourceorigin_common::protocol::jwt::{
    Algorithm, Claim, Jwk, JwkSet, KeyId, KeyType, KeyUse, TokenType,
};
use std::{borrow::Cow, collections::BTreeSet};

/// RSA key size used by generated keys.
const GENERATED_RSA_SIZE: KeySize = KeySize::Rsa3072;
/// The PEM label of a PKCS#8 private key.
const PKCS8_LABEL: &str = "PRIVATE KEY";
/// The PEM label of a public key.
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";
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

/// A compact token with auth's header parsed, but nothing verified.
struct Token<'a> {
    /// The parsed protected header.
    header: Header<'static>,
    /// The token's parts.
    compact: Compact<'a>,
}

impl<'a> Token<'a> {
    /// Splits a bounded token into exactly three parts and parses its header.
    fn parse(token: &'a str) -> Result<Self, CryptoError> {
        let split = Compact::split(token).map_err(|_| CryptoError::InvalidToken)?;
        Ok(Self {
            header: serde_json::from_slice(split.header())?,
            compact: split.decode().map_err(|_| CryptoError::InvalidToken)?,
        })
    }
}

/// A public signing key, as JWKS publishes it: what verifies the tokens it signed.
#[derive(Clone)]
pub struct PublicKey {
    /// The published form.
    jwk: Jwk,
    /// The key that verifies its RS256 signatures, which has no defect.
    key: Rs256VerifyingKey,
}

impl PublicKey {
    /// Builds the key a JWK describes.
    ///
    /// # Errors
    /// Rejects malformed keys, keys every SDK would refuse to verify with, and
    /// invalid key identifiers.
    pub fn from_jwk(jwk: Jwk) -> Result<Self, CryptoError> {
        jwk.kid.parse::<KeyId>().map_err(|_| CryptoError::KeyId)?;
        let key = match jwk.kty {
            KeyType::Rsa => Rs256VerifyingKey::new(
                &URL_SAFE_NO_PAD.decode(&jwk.n)?,
                &URL_SAFE_NO_PAD.decode(&jwk.e)?,
            ),
        };
        if let Some(defect) = key.defect() {
            return Err(CryptoError::UnusableKey(defect));
        }
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

    /// The key's JWK thumbprint (RFC 7638): the SHA-256 digest of its required
    /// members, in lexicographic order and canonical form, so it names the key
    /// itself, whatever its `kid` or how its JWK spells it.
    #[must_use]
    pub fn thumbprint(&self) -> Digest {
        let members = match self.jwk.kty {
            // Base64url never needs escaping in JSON.
            KeyType::Rsa => format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(self.key.exponent()),
                URL_SAFE_NO_PAD.encode(self.key.modulus()),
            ),
        };
        Digest::sha256(members.as_bytes())
    }

    /// Exports the key as PEM, `SubjectPublicKeyInfo` in the form `openssl`
    /// writes, for independent verifiers.
    #[must_use]
    pub fn pem(&self) -> String {
        // `from_jwk` refused a key with a defect, so this one has its DER.
        Pem::encode(PUBLIC_KEY_LABEL, self.key.der().unwrap_or_default())
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
        token: &Token<'_>,
        typ: TokenType,
        issuer: &str,
    ) -> Result<Value, CryptoError> {
        if token.header.typ != typ || !self.signs_with(token.header.alg) {
            return Err(CryptoError::InvalidToken);
        }
        self.key
            .verify(token.compact.signing_input(), token.compact.signature())
            .map_err(|error| match error {
                VerifyError::Unusable(defect) => CryptoError::UnusableKey(defect),
                VerifyError::BadSignature => CryptoError::Signature,
            })?;
        let claims: Value = serde_json::from_slice(token.compact.payload())?;
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
    key: RsaKeyPair,
    /// The public half, derived once from the private key.
    public: PublicKey,
}

impl Rs256Key {
    /// Loads a PKCS#8 PEM RSA private key (`PRIVATE KEY`) under `kid`, for test
    /// fixtures.
    ///
    /// # Errors
    /// Returns an error for invalid PEM, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_pem(kid: impl Into<String>, pem: &str) -> Result<Self, CryptoError> {
        let der = Pem::decode(pem, PKCS8_LABEL).ok_or(CryptoError::Pem)?;
        Self::from_key(kid.into(), RsaKeyPair::from_pkcs8(&der)?)
    }

    /// Loads a PKCS#8 DER RSA private key under `kid`, as [`Self::private_key_der`] exports it.
    ///
    /// # Errors
    /// Returns an error for invalid DER, a non-RSA or undersized key, or an invalid identifier.
    pub fn from_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, CryptoError> {
        Self::from_key(kid.into(), RsaKeyPair::from_pkcs8(der)?)
    }

    /// Generates a 3072-bit RSA key using the configured cryptographic provider.
    ///
    /// # Errors
    /// Preserves provider failures and rejects invalid key identifiers.
    pub fn generate(kid: impl Into<String>) -> Result<Self, CryptoError> {
        Self::from_key(kid.into(), RsaKeyPair::generate(GENERATED_RSA_SIZE)?)
    }

    /// Validates RSA size and key identifier for every construction path. The
    /// provider refuses keys under 2048 bits before this runs.
    fn from_key(kid: String, key: RsaKeyPair) -> Result<Self, CryptoError> {
        let public = key.public_key();
        let public = PublicKey::from_jwk(Jwk {
            alg: Some(Algorithm::Rs256),
            e: URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
            key_ops: None,
            kid: kid.clone(),
            kty: KeyType::Rsa,
            n: URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
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
        let der: Pkcs8V1Der<'_> = self.key.as_der()?;
        Ok(der.as_ref().to_vec())
    }

    /// Exports the private key as PKCS#8 PEM, for test fixtures.
    ///
    /// # Errors
    /// Preserves encoding failures from the provider.
    pub fn private_key_pem(&self) -> Result<String, CryptoError> {
        Ok(Pem::encode(PKCS8_LABEL, &self.private_key_der()?))
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
        self.signed(&format!("{header}.{payload}"))
    }

    /// The compact token of `input`, `header.payload`, with its RS256 signature.
    fn signed(&self, input: &str) -> Result<String, CryptoError> {
        let mut signature = vec![0; self.key.public_modulus_len()];
        // RSASSA-PKCS1-v1_5 is deterministic: the provider ignores the generator.
        self.key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
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
        let token = Token::parse(token)?;
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
        let token = Token::parse(token)?;
        Self::find(&self.published, &token)
            .or_else(|_| Self::find(&self.retired, &token))?
            .verified(&token, TokenType::Id, issuer)
    }

    /// The key among `keys` that `token` names.
    fn find<'k>(keys: &'k [PublicKey], token: &Token<'_>) -> Result<&'k PublicKey, CryptoError> {
        keys.iter()
            .find(|key| key.kid() == token.header.kid)
            .ok_or(CryptoError::UnknownKey)
    }
}

/// PEM (RFC 7468): base64 DER between `-----BEGIN <label>-----` and
/// `-----END <label>-----` lines.
struct Pem;

impl Pem {
    /// The DER of the first block labelled `label` in `text`, if it decodes.
    fn decode(text: &str, label: &str) -> Option<Vec<u8>> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = text.split_once(&begin)?.1.split_once(&end)?.0;
        let base64: String = body.split_whitespace().collect();
        STANDARD.decode(base64).ok()
    }

    /// `der` as a block labelled `label`, in lines of 64 characters.
    fn encode(label: &str, der: &[u8]) -> String {
        let base64 = STANDARD.encode(der);
        let mut lines = String::new();
        // Base64 is ASCII, so any split falls between characters.
        let mut rest = base64.as_str();
        while !rest.is_empty() {
            let (line, tail) = rest.split_at(rest.len().min(64));
            lines.push_str(line);
            lines.push('\n');
            rest = tail;
        }
        format!("-----BEGIN {label}-----\n{lines}-----END {label}-----\n")
    }
}

#[cfg(test)]
mod tests;
