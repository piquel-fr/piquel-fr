//! Conservative email equality policy; see `docs/security/email-normalization.md`.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Maximum byte length of a normalized email address.
const MAX_EMAIL_BYTES: usize = 254;
/// Maximum byte length of the local component.
const MAX_LOCAL_BYTES: usize = 64;
/// Maximum byte length of a DNS label.
const MAX_DOMAIN_LABEL_BYTES: usize = 63;

/// Reasons an address cannot be used for conservative email equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(super) enum InvalidEmail {
    /// The address is empty or exceeds the storage limit.
    #[error("email must contain 1 to 254 bytes")]
    Length,
    /// Whitespace and control characters are never accepted.
    #[error("email cannot contain whitespace or control characters")]
    ForbiddenCharacter,
    /// The separator between local and domain components is absent.
    #[error("email must contain a local part and domain separated by @")]
    MissingSeparator,
    /// The local component is ambiguous or exceeds its byte limit.
    #[error("email local part is invalid")]
    LocalPart,
    /// The domain contains invalid labels or has no domain suffix.
    #[error("email domain is invalid")]
    Domain,
}

/// An NFC-normalized address whose local part retains case, dots and plus tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Applies the conservative equality policy documented in `docs/security/email-normalization.md`.
    /// Provider-specific local-part equivalence never grants account ownership.
    pub(super) fn parse(value: &str) -> Result<Self, InvalidEmail> {
        if value.is_empty() || value.len() > MAX_EMAIL_BYTES {
            return Err(InvalidEmail::Length);
        }
        if value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(InvalidEmail::ForbiddenCharacter);
        }
        let (local, domain) = value
            .rsplit_once('@')
            .ok_or(InvalidEmail::MissingSeparator)?;
        if local.is_empty()
            || local.len() > MAX_LOCAL_BYTES
            || local.contains('@')
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
        {
            return Err(InvalidEmail::LocalPart);
        }
        let local = local.nfc().collect::<String>();
        let domain = domain.nfc().collect::<String>().to_lowercase();
        let normalized = format!("{local}@{domain}");
        if local.len() > MAX_LOCAL_BYTES {
            return Err(InvalidEmail::LocalPart);
        }
        if normalized.len() > MAX_EMAIL_BYTES {
            return Err(InvalidEmail::Length);
        }
        if !Self::valid_domain(&domain) {
            return Err(InvalidEmail::Domain);
        }
        Ok(Self(normalized))
    }

    /// Returns the normalized representation used for exact database equality.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// Requires at least two nonempty DNS-style labels without leading or trailing hyphens.
    fn valid_domain(domain: &str) -> bool {
        let mut count = 0;
        let valid = domain.split('.').all(|label| {
            count += 1;
            !(label.is_empty()
                || label.len() > MAX_DOMAIN_LABEL_BYTES
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '-'))
        });
        valid && count >= 2
    }
}

#[cfg(test)]
mod tests {
    //! Focused coverage of the conservative equality and rejection policies.
    use super::{InvalidEmail, NormalizedEmail};

    /// Provider-specific dot and plus equivalence must never merge addresses.
    #[test]
    fn preserves_provider_specific_local_part_semantics() {
        assert_eq!(
            NormalizedEmail::parse("Ada+jobs@Example.COM")
                .expect("valid email")
                .as_str(),
            "Ada+jobs@example.com"
        );
        assert_ne!(
            NormalizedEmail::parse("a.da@example.com"),
            NormalizedEmail::parse("ada@example.com")
        );
    }

    /// Ambiguous addresses fail with a useful policy reason.
    #[test]
    fn rejects_ambiguous_values() {
        for (value, reason) in [
            ("not-an-email", InvalidEmail::MissingSeparator),
            ("a@b@example.com", InvalidEmail::LocalPart),
            ("a b@example.com", InvalidEmail::ForbiddenCharacter),
            ("a@example..com", InvalidEmail::Domain),
            ("a@-example.com", InvalidEmail::Domain),
            (" a@example.com", InvalidEmail::ForbiddenCharacter),
        ] {
            assert_eq!(NormalizedEmail::parse(value), Err(reason));
        }
    }

    /// Canonical Unicode composition and byte limits apply before storage.
    #[test]
    fn normalizes_unicode_and_enforces_component_limits() {
        assert_eq!(
            NormalizedEmail::parse("e\u{301}@EXAMPLE.COM")
                .expect("email")
                .as_str(),
            "é@example.com"
        );
        assert!(NormalizedEmail::parse(&format!("{}@example.com", "a".repeat(64))).is_ok());
        assert_eq!(
            NormalizedEmail::parse(&format!("{}@example.com", "a".repeat(65))),
            Err(InvalidEmail::LocalPart)
        );
        assert_eq!(
            NormalizedEmail::parse(&format!("a@{}.com", "a".repeat(64))),
            Err(InvalidEmail::Domain)
        );
    }
}
