//! Ed25519 signed notes in the C2SP signed-note format (<https://c2sp.org/signed-note>),
//! which audit checkpoints use.
//!
//! A note is UTF-8 text ending in a newline, a blank line, then one line per
//! signature: `— <key name> <base64(key ID || signature)>`. The key ID is the first
//! four bytes of `SHA-256(name || "\n" || 0x01 || public key)`, so a verifier
//! recognizes its own signatures and ignores others. Verifier keys are written
//! `<name>+<hex key ID>+<base64(0x01 || public key)>`.
use super::{CryptoError, Digest};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    pkey::{Id, PKey, Private},
    sign::{Signer, Verifier},
};
use rand::{RngCore, rngs::OsRng};
use std::{fmt, str::FromStr};

/// Identifies Ed25519 in key IDs and verifier keys.
const ED25519: u8 = 0x01;
/// Starts every signature line: an em dash and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";
/// Byte length of an Ed25519 seed, which is its private key.
const SEED_BYTES: usize = 32;
/// Byte length of an Ed25519 public key.
const PUBLIC_KEY_BYTES: usize = 32;
/// Byte length of a key ID.
const KEY_ID_BYTES: usize = 4;

/// An Ed25519 key that signs notes under its name, e.g. `auth.piquel.fr/audit`.
pub struct NoteKey {
    /// The private key.
    key: PKey<Private>,
    /// The name and public key that check its signatures.
    verifier: NoteVerifier,
}

impl NoteKey {
    /// Loads a key from its seed written as 64 hexadecimal characters, as a
    /// generated secret holds it. One trailing newline is ignored.
    ///
    /// # Errors
    /// Rejects a name that is empty or contains whitespace or `+`, and a seed
    /// that is not exactly 32 hex-encoded bytes.
    pub fn from_hex_seed(name: &str, hex: &str) -> Result<Self, CryptoError> {
        let hex = hex.strip_suffix('\n').unwrap_or(hex);
        if hex.len() != SEED_BYTES * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CryptoError::NoteKeySeed);
        }
        // Every character is an ASCII hex digit, so each pair is a valid slice, and
        // `from_str_radix` never sees the sign it would otherwise accept.
        let mut seed = [0; SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| CryptoError::NoteKeySeed)?;
        }
        Self::from_seed(name, &seed)
    }

    /// Generates a key using operating system randomness, for tests and previews.
    ///
    /// # Errors
    /// Rejects an invalid name and preserves failures from the random source.
    pub fn generate(name: &str) -> Result<Self, CryptoError> {
        let mut seed = [0; SEED_BYTES];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(CryptoError::Random)?;
        Self::from_seed(name, &seed)
    }

    /// Builds the key and its verifier from a 32-byte seed.
    fn from_seed(name: &str, seed: &[u8; SEED_BYTES]) -> Result<Self, CryptoError> {
        let key = PKey::private_key_from_raw_bytes(seed, Id::ED25519)?;
        let public = key
            .raw_public_key()?
            .try_into()
            .map_err(|_| CryptoError::NoteKeySeed)?;
        Ok(Self {
            key,
            verifier: NoteVerifier::new(name, public)?,
        })
    }

    /// The name and public key that verify this key's notes.
    #[must_use]
    pub const fn verifier(&self) -> &NoteVerifier {
        &self.verifier
    }

    /// Signs `text`, which must end with a newline and contain no other control
    /// characters, and returns the signed note.
    ///
    /// # Errors
    /// Rejects invalid text and preserves provider failures.
    pub fn sign(&self, text: &str) -> Result<String, CryptoError> {
        NoteVerifier::check_text(text)?;
        let signature =
            Signer::new_without_digest(&self.key)?.sign_oneshot_to_vec(text.as_bytes())?;
        let mut signed = self.verifier.id.to_be_bytes().to_vec();
        signed.extend(signature);
        Ok(format!(
            "{text}\n{SIGNATURE_PREFIX}{} {}\n",
            self.verifier.name,
            STANDARD.encode(signed)
        ))
    }
}

impl fmt::Debug for NoteKey {
    /// Shows the verifier, never the private key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoteKey")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

/// A key name and Ed25519 public key that check note signatures. Displays as a
/// verifier key, `<name>+<hex key ID>+<base64(0x01 || public key)>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteVerifier {
    /// The signer's name.
    name: String,
    /// Identifies the key in signature lines.
    id: u32,
    /// The Ed25519 public key.
    public: [u8; PUBLIC_KEY_BYTES],
}

impl NoteVerifier {
    /// Builds a verifier, computing its key ID.
    fn new(name: &str, public: [u8; PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        if name.is_empty() || name.contains(|c: char| c.is_whitespace() || c == '+') {
            return Err(CryptoError::NoteKeyName);
        }
        let mut input = format!("{name}\n").into_bytes();
        input.push(ED25519);
        input.extend(public);
        let digest = Digest::sha256(&input);
        let mut id = [0; KEY_ID_BYTES];
        id.copy_from_slice(&digest.as_bytes()[..KEY_ID_BYTES]);
        Ok(Self {
            name: name.to_owned(),
            id: u32::from_be_bytes(id),
            public,
        })
    }

    /// Parses a verifier key, `<name>+<hex key ID>+<base64(0x01 || public key)>`.
    ///
    /// # Errors
    /// Rejects malformed keys, keys other than Ed25519, and a key ID that does
    /// not match the name and public key.
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        value.parse()
    }

    /// The signer's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Rejects note text that does not end with a newline, or holds another control
    /// character, so a note's text and signatures cannot be confused.
    fn check_text(text: &str) -> Result<(), CryptoError> {
        if text.ends_with('\n') && text.chars().all(|c| c == '\n' || !c.is_control()) {
            Ok(())
        } else {
            Err(CryptoError::NoteText)
        }
    }

    /// Whether `signature` is this key's Ed25519 signature of `text`.
    fn verifies(&self, text: &str, signature: &[u8]) -> Result<bool, CryptoError> {
        let key = PKey::public_key_from_raw_bytes(&self.public, Id::ED25519)?;
        // OpenSSL reports a malformed signature as an error rather than `false`.
        Ok(Verifier::new_without_digest(&key)?
            .verify_oneshot(signature, text.as_bytes())
            .unwrap_or(false))
    }
}

impl FromStr for NoteVerifier {
    type Err = CryptoError;

    /// See [`NoteVerifier::parse`].
    fn from_str(value: &str) -> Result<Self, CryptoError> {
        // Names hold no `+`, but base64 keys may.
        let mut parts = value.splitn(3, '+');
        let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(CryptoError::NoteVerifierKey);
        };
        let key = STANDARD
            .decode(key)
            .map_err(|_| CryptoError::NoteVerifierKey)?;
        let Some((&ED25519, public)) = key.split_first() else {
            return Err(CryptoError::NoteVerifierKey);
        };
        let public = public
            .try_into()
            .map_err(|_| CryptoError::NoteVerifierKey)?;
        let verifier = Self::new(name, public)?;
        if id.len() != KEY_ID_BYTES * 2 || u32::from_str_radix(id, 16).ok() != Some(verifier.id) {
            return Err(CryptoError::NoteVerifierKey);
        }
        Ok(verifier)
    }
}

impl fmt::Display for NoteVerifier {
    /// Writes the verifier key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut key = vec![ED25519];
        key.extend(self.public);
        write!(
            formatter,
            "{}+{:08x}+{}",
            self.name,
            self.id,
            STANDARD.encode(key)
        )
    }
}

/// The keys a note may be signed with, e.g. the current audit key and those it
/// replaced. Written one verifier key per line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoteVerifiers(Vec<NoteVerifier>);

impl NoteVerifiers {
    /// Parses one verifier key per line, ignoring blank lines.
    ///
    /// # Errors
    /// Rejects any malformed key.
    pub fn parse(lines: &str) -> Result<Self, CryptoError> {
        lines
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(NoteVerifier::parse)
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// Whether no key is listed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `verifier` is listed.
    #[must_use]
    pub fn contains(&self, verifier: &NoteVerifier) -> bool {
        self.0.contains(verifier)
    }

    /// Adds `verifier`, unless it is already listed.
    pub fn insert(&mut self, verifier: NoteVerifier) {
        if !self.contains(&verifier) {
            self.0.push(verifier);
        }
    }

    /// Checks `note` and returns its text. Signatures by keys not listed are
    /// ignored, but at least one listed key must have signed it, and no signature
    /// claiming to be by a listed key may be invalid.
    ///
    /// # Errors
    /// Rejects malformed notes, invalid signatures by listed keys, and notes no
    /// listed key signed.
    pub fn open<'a>(&self, note: &'a str) -> Result<&'a str, CryptoError> {
        let split = note.rfind("\n\n").ok_or(CryptoError::NoteFormat)?;
        let (text, signatures) = (&note[..=split], &note[split + 2..]);
        NoteVerifier::check_text(text)?;
        let signatures = signatures
            .strip_suffix('\n')
            .ok_or(CryptoError::NoteFormat)?;
        let mut verified = false;
        for line in signatures.split('\n') {
            let (name, signature) = line
                .strip_prefix(SIGNATURE_PREFIX)
                .and_then(|line| line.rsplit_once(' '))
                .ok_or(CryptoError::NoteFormat)?;
            let signature = STANDARD
                .decode(signature)
                .map_err(|_| CryptoError::NoteFormat)?;
            if signature.len() <= KEY_ID_BYTES {
                return Err(CryptoError::NoteFormat);
            }
            let (id, signature) = signature.split_at(KEY_ID_BYTES);
            let id = u32::from_be_bytes(id.try_into().map_err(|_| CryptoError::NoteFormat)?);
            for verifier in self.0.iter().filter(|key| key.name == name && key.id == id) {
                if !verifier.verifies(text, signature)? {
                    return Err(CryptoError::NoteSignature);
                }
                verified = true;
            }
        }
        if verified {
            Ok(text)
        } else {
            Err(CryptoError::NoteUnverified)
        }
    }
}

impl From<NoteVerifier> for NoteVerifiers {
    /// Lists one key.
    fn from(verifier: NoteVerifier) -> Self {
        Self(vec![verifier])
    }
}

impl fmt::Display for NoteVerifiers {
    /// Writes one verifier key per line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|verifier| writeln!(formatter, "{verifier}"))
    }
}
