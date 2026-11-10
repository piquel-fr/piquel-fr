//! The keys auth reads from the environment: the key-encryption key, which
//! `AuthConfig` opens, the token digest keys, the link keys derived from them, and
//! the audit checkpoint key.

use crate::{
    AuditKeys,
    emails::VerificationKeys,
    notifications::{SignOutLinks, UnsubscribeLinks},
    recovery::RecoveryLinks,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sourceorigin_common::config::{
    ConfigurationError, Origin, SecretBytes, SecretReference, Variable,
};
use sourceorigin_crypto::{CryptoError, Digest, NoteKey, NoteVerifier, Secret};
use std::sync::Arc;

/// Separates opaque token digests from every other use of a token digest key. The
/// PEM signing key was used the same way, so it still works as a token digest key.
const TOKEN_DIGEST_CONTEXT: &[u8] = b"sourceorigin-refresh-token-digest-v1";
/// Separates the email verification key from every other use of a token digest
/// key.
const EMAIL_VERIFICATION_CONTEXT: &[u8] = b"sourceorigin-email-verification-token-v1";
/// Separates the recovery link key from every other use of a token digest key,
/// as [`EMAIL_VERIFICATION_CONTEXT`] does the verification key.
const RECOVERY_LINK_CONTEXT: &[u8] = b"sourceorigin-account-recovery-link-v1";
/// Separates the unsubscribe link key from every other use of a token digest
/// key, as [`EMAIL_VERIFICATION_CONTEXT`] does the verification key.
const UNSUBSCRIBE_LINK_CONTEXT: &[u8] = b"sourceorigin-email-unsubscribe-link-v1";
/// Separates the sign-out link key from every other use of a token digest key,
/// as [`EMAIL_VERIFICATION_CONTEXT`] does the verification key.
const SIGN_OUT_LINK_CONTEXT: &[u8] = b"sourceorigin-email-sign-out-link-v1";
/// Fewest bytes a token digest key may have.
const MIN_TOKEN_DIGEST_KEY_BYTES: usize = 32;
/// Bytes of a token digest key's digest kept as its fingerprint.
const DIGEST_KEY_FINGERPRINT_BYTES: usize = 8;

sourceorigin_common::variables! {
    /// The keys' variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    /// Where to read the key that seals signing keys in the database: 32 bytes as
    /// unpadded base64url text, through `env://NAME` or `file:///path`. A trailing
    /// newline is ignored. Required. It can't be changed yet: the stored signing
    /// keys would no longer open.
    pub(super) const KEY_ENCRYPTION_KEY = "AUTH_KEY_ENCRYPTION_KEY";
    /// Where to read the key under which refresh tokens, authorization codes and
    /// pending logins are stored as HMAC digests. Its raw bytes are the key, at
    /// least 32 of them. Email verification, recovery and unsubscribe links derive
    /// from it too.
    /// Required. Replacing it at once ends every refresh token and every login in
    /// progress, so change it in two deploys.
    const TOKEN_DIGEST_KEY = "AUTH_TOKEN_DIGEST_KEY";
    /// Where to read another token digest key, accepted but never used for new
    /// digests: the next key before it becomes current, or the old one after.
    const TOKEN_DIGEST_KEY_ACCEPTED = "AUTH_TOKEN_DIGEST_KEY_ACCEPTED";
    /// Where to read the key that signs audit checkpoints: a 32-byte Ed25519 seed
    /// as 64 hex characters. Required.
    const AUDIT_KEY_PROVIDER = "AUTH_AUDIT_KEY_PROVIDER";
}

/// One key under which opaque token secrets are stored as HMAC digests.
pub(crate) struct TokenDigestKey {
    /// The HMAC key, derived from the configured bytes.
    key: Secret,
    /// Identifies the key in stored records, without revealing it.
    fingerprint: String,
    /// The email verification key, derived from the same bytes. It derives new
    /// links' tokens while this key is current, and rebuilds queued ones while it
    /// is accepted ([`LinkKeys`]).
    verification: Secret,
    /// The recovery link key, derived and used like [`Self::verification`].
    recovery: Secret,
    /// The unsubscribe link key, derived like [`Self::verification`]. Its links
    /// are checked by deriving them again, under either key.
    unsubscribe: Secret,
    /// The sign-out link key, derived and checked like [`Self::unsubscribe`].
    sign_out: Secret,
}

impl TokenDigestKey {
    /// Derives the HMAC, verification, recovery, unsubscribe and sign-out link
    /// keys from configured bytes, as the PEM key's always were.
    pub(crate) fn derive(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = Secret::derive(bytes, TOKEN_DIGEST_CONTEXT)?;
        let fingerprint = URL_SAFE_NO_PAD
            .encode(&Digest::sha256(key.as_bytes()).as_bytes()[..DIGEST_KEY_FINGERPRINT_BYTES]);
        Ok(Self {
            key,
            fingerprint,
            verification: Secret::derive(bytes, EMAIL_VERIFICATION_CONTEXT)?,
            recovery: Secret::derive(bytes, RECOVERY_LINK_CONTEXT)?,
            unsubscribe: Secret::derive(bytes, UNSUBSCRIBE_LINK_CONTEXT)?,
            sign_out: Secret::derive(bytes, SIGN_OUT_LINK_CONTEXT)?,
        })
    }

    /// The digest of `secret` under this key.
    fn digest(&self, secret: &Secret) -> Result<Digest, CryptoError> {
        Digest::hmac(self.key.as_bytes(), secret.as_bytes())
    }
}

/// The token digest keys: the current one makes every new digest, and during a
/// change of key another one is accepted too. A change takes two deploys, so a
/// release never issues a digest the release beside it cannot check: the first
/// accepts the next key, the second makes it current and accepts the old one.
pub struct TokenDigestKeys {
    /// Makes new digests.
    current: TokenDigestKey,
    /// Also accepted.
    accepted: Option<TokenDigestKey>,
}

impl TokenDigestKeys {
    /// Recovery links on `origin`, under the current key's recovery key, and
    /// rebuilt under the accepted one's for recoveries started before a change.
    pub(crate) fn recovery_links(&self, origin: &Origin) -> RecoveryLinks {
        RecoveryLinks::new(origin.clone(), self.link_keys(|key| &key.recovery))
    }

    /// Unsubscribe links on `origin`, under the current key's unsubscribe key,
    /// and accepted under the accepted one's.
    pub(crate) fn unsubscribe_links(&self, origin: &Origin) -> UnsubscribeLinks {
        UnsubscribeLinks::new(origin.clone(), self.link_keys(|key| &key.unsubscribe))
    }

    /// Sign-out links on `origin`, under the current key's sign-out key, and
    /// accepted under the accepted one's.
    pub(crate) fn sign_out_links(&self, origin: &Origin) -> SignOutLinks {
        SignOutLinks::new(origin.clone(), self.link_keys(|key| &key.sign_out))
    }

    /// Verification tokens under the current key's verification key, rebuilt
    /// under the accepted one's for addresses added before a change.
    pub(crate) fn verification_keys(&self) -> VerificationKeys {
        VerificationKeys::new(self.link_keys(|key| &key.verification))
    }

    /// The link keys `key` picks from the current key, then the accepted one.
    fn link_keys(&self, key: fn(&TokenDigestKey) -> &Secret) -> LinkKeys {
        let accepted = self.accepted.as_ref().map(|accepted| key(accepted).clone());
        LinkKeys::new(key(&self.current).clone(), accepted)
    }

    /// Uses `current` for new digests and accepts `accepted` too.
    pub(crate) const fn new(current: TokenDigestKey, accepted: Option<TokenDigestKey>) -> Self {
        Self { current, accepted }
    }

    /// Reads `AUTH_TOKEN_DIGEST_KEY` and `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`.
    ///
    /// # Errors
    /// Names a missing or unreadable key, or one shorter than 32 bytes.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        let derive = |variable: Variable, bytes: SecretBytes| {
            TokenDigestKey::derive(bytes.expose_secret())
                .map_err(|source| variable.error("could not derive a key", source))
        };
        let current = derive(TOKEN_DIGEST_KEY, Self::read(TOKEN_DIGEST_KEY)?)?;
        let accepted = TOKEN_DIGEST_KEY_ACCEPTED
            .optional()?
            .map(|_| {
                derive(
                    TOKEN_DIGEST_KEY_ACCEPTED,
                    Self::read(TOKEN_DIGEST_KEY_ACCEPTED)?,
                )
            })
            .transpose()?;
        Ok(Self::new(current, accepted))
    }

    /// Resolves the key `variable` references; its raw bytes are the key.
    fn read(variable: Variable) -> Result<SecretBytes, ConfigurationError> {
        let reference: SecretReference = variable.parse()?;
        let bytes = reference.resolve().map_err(|source| {
            variable.error("must resolve through env://NAME or file://PATH", source)
        })?;
        if bytes.expose_secret().len() < MIN_TOKEN_DIGEST_KEY_BYTES {
            return Err(variable.invalid("must contain at least 32 bytes"));
        }
        Ok(bytes)
    }

    /// The digest a new `secret` is stored as, and its key's fingerprint.
    pub(crate) fn issue(&self, secret: &Secret) -> Result<(Digest, &str), CryptoError> {
        Ok((self.current.digest(secret)?, &self.current.fingerprint))
    }

    /// Every digest a presented `secret` may be stored as, one per accepted key.
    pub(crate) fn accepted(&self, secret: &Secret) -> Result<Vec<Vec<u8>>, CryptoError> {
        [Some(&self.current), self.accepted.as_ref()]
            .into_iter()
            .flatten()
            .map(|key| Ok(key.digest(secret)?.as_bytes().to_vec()))
            .collect()
    }

    /// Names the key a stored fingerprint belongs to: `current`, `accepted`,
    /// `unrecorded` for digests made before fingerprints were stored, under the
    /// PEM key's derivation, or `unknown`.
    #[must_use]
    pub fn name(&self, fingerprint: Option<&str>) -> &'static str {
        let Some(fingerprint) = fingerprint else {
            return "unrecorded";
        };
        if fingerprint == self.current.fingerprint {
            "current"
        } else if self
            .accepted
            .as_ref()
            .is_some_and(|accepted| fingerprint == accepted.fingerprint)
        {
            "accepted"
        } else {
            "unknown"
        }
    }
}

/// The keys of one kind of emailed link, each deriving a link's token from the
/// ID of what the link acts on: the current one, which derives every new token,
/// then the one accepted during a change of token digest key, if any. A link is
/// checked against its token's stored SHA-256 digest, never derived again, so a
/// change of key never breaks a link already sent, and the email sender rebuilds
/// a link still queued under whichever key made its digest.
#[derive(Clone)]
pub(crate) struct LinkKeys(Arc<[Secret]>);

impl LinkKeys {
    /// Derives new tokens with `current`, and rebuilds those `accepted` made.
    pub(crate) fn new(current: Secret, accepted: Option<Secret>) -> Self {
        Self(std::iter::once(current).chain(accepted).collect())
    }

    /// The token of a new link for the ID whose bytes are `id`, under the current
    /// key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn token(&self, id: &[u8; 16]) -> Result<Secret, CryptoError> {
        Self::derive(&self.0[0], id)
    }

    /// The token for `id` whose SHA-256 is the stored `digest`, under the key that
    /// derives it. `None` once no configured key does.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn rebuild(
        &self,
        id: &[u8; 16],
        digest: &[u8],
    ) -> Result<Option<Secret>, CryptoError> {
        for key in self.0.iter() {
            let token = Self::derive(key, id)?;
            if token.digest().as_bytes() == digest {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }

    /// Whether a configured key derives `presented` for `id`, compared in
    /// constant time: how a link whose token is stored nowhere is checked.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn derives(&self, id: &[u8; 16], presented: &Secret) -> Result<bool, CryptoError> {
        let mut derived = false;
        for key in self.0.iter() {
            let token = Self::derive(key, id)?;
            derived |= Digest::constant_time_eq(token.as_bytes(), presented.as_bytes());
        }
        Ok(derived)
    }

    /// The token `key` derives for `id`.
    fn derive(key: &Secret, id: &[u8; 16]) -> Result<Secret, CryptoError> {
        Secret::derive(key.as_bytes(), id)
    }
}

#[cfg(test)]
impl LinkKeys {
    /// A fresh current key, and none accepted.
    pub(crate) fn generate() -> Self {
        Self::new(Secret::generate().expect("link key"), None)
    }
}

/// The key that signs audit checkpoints: an Ed25519 key of its own, so it rotates
/// independently of the OIDC signing keys. See `docs/dev/security/audit-history.md`.
#[derive(Clone)]
pub struct AuditConfig {
    /// Signs checkpoints as `<auth host>/audit`.
    pub(crate) key: Arc<NoteKey>,
    /// Verifies the checkpoints the sealer builds on and auth publishes as the
    /// latest: the environment's committed keys and this one.
    pub(crate) keys: Arc<AuditKeys>,
}

impl AuditConfig {
    /// Reads the key from `AUTH_AUDIT_KEY_PROVIDER` and names it after `origin`.
    ///
    /// # Errors
    /// Names the variable when it is missing, does not resolve, or does not hold a
    /// 32-byte seed in hex.
    pub fn from_environment(origin: &Origin) -> Result<Self, ConfigurationError> {
        let reference: SecretReference = AUDIT_KEY_PROVIDER.parse()?;
        let secret = reference.resolve().map_err(|source| {
            AUDIT_KEY_PROVIDER.error("must resolve to a 32-byte Ed25519 seed in hex", source)
        })?;
        Self::parse(origin, &secret)
    }

    /// Decodes the seed: 64 hex characters, with one trailing newline allowed, as
    /// `openssl rand -hex 32` or a piqueld `{ type = "random", bytes = 32, encoding =
    /// "hex" }` secret writes it.
    pub(crate) fn parse(origin: &Origin, secret: &SecretBytes) -> Result<Self, ConfigurationError> {
        let reason = "must contain a 32-byte Ed25519 seed as 64 hexadecimal characters";
        let hex = secret
            .utf8()
            .map_err(|source| AUDIT_KEY_PROVIDER.error(reason, source))?;
        let key = NoteKey::from_hex_seed(&AuditKeys::name(origin), hex)
            .map_err(|source| AUDIT_KEY_PROVIDER.error(reason, source))?;
        Self::new(origin, key)
    }

    /// Signs with `key` for the environment at `origin`.
    ///
    /// # Errors
    /// Fails only if the committed audit keys, compiled in, are malformed.
    pub(crate) fn new(origin: &Origin, key: NoteKey) -> Result<Self, ConfigurationError> {
        let keys = AuditKeys::for_sealer(origin, key.verifier()).map_err(|source| {
            AUDIT_KEY_PROVIDER.error("needs well-formed committed audit keys", source)
        })?;
        Ok(Self {
            key: Arc::new(key),
            keys: Arc::new(keys),
        })
    }

    /// The name and public key that verify checkpoints, to commit to
    /// `docs/dev/security/audit-key.pub`.
    #[must_use]
    pub fn verifier(&self) -> &NoteVerifier {
        self.key.verifier()
    }
}
