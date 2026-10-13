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
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(super) enum InvalidEmail {
    /// The address is empty.
    #[error("email is empty")]
    Empty,
    /// The address, before or after normalization, exceeds the storage limit.
    #[error("email is {0} bytes; at most {MAX_EMAIL_BYTES} are allowed")]
    TooLong(usize),
    /// Whitespace and control characters are never accepted.
    #[error("email cannot contain whitespace or control characters")]
    ForbiddenCharacter,
    /// The separator between local and domain components is absent.
    #[error("email must contain a local part and domain separated by @")]
    MissingSeparator,
    /// More than one `@`; quoted local parts are not supported.
    #[error("email must contain exactly one @")]
    MultipleSeparators,
    /// Nothing precedes the `@`.
    #[error("email has nothing before the @")]
    EmptyLocalPart,
    /// The local part, before or after normalization, exceeds its byte limit.
    #[error("email local part is {0} bytes; at most {MAX_LOCAL_BYTES} are allowed")]
    LocalPartTooLong(usize),
    /// A dot starts or ends the local part, or two dots are adjacent.
    #[error("email local part cannot start or end with a dot or contain two consecutive dots")]
    LocalPartDots,
    /// Nothing follows the `@`.
    #[error("email has nothing after the @")]
    EmptyDomain,
    /// The domain has a single label, such as `localhost`.
    #[error("email domain {0:?} needs a suffix, such as example.com")]
    DomainWithoutSuffix(String),
    /// A dot starts or ends the domain, or two dots are adjacent.
    #[error("email domain {0:?} has an empty label")]
    EmptyDomainLabel(String),
    /// A domain label exceeds the DNS label limit.
    #[error("email domain label {0:?} is longer than {MAX_DOMAIN_LABEL_BYTES} bytes")]
    DomainLabelTooLong(String),
    /// A domain label starts or ends with a hyphen.
    #[error("email domain label {0:?} cannot start or end with a hyphen")]
    DomainLabelHyphen(String),
    /// A domain label contains something other than letters, digits and hyphens.
    #[error("email domain label {0:?} can only contain letters, digits and hyphens")]
    DomainLabelCharacter(String),
}

/// An NFC-normalized address whose local part retains case, dots and plus tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Applies the conservative equality policy documented in `docs/security/email-normalization.md`.
    /// Provider-specific local-part equivalence never grants account ownership.
    pub(super) fn parse(value: &str) -> Result<Self, InvalidEmail> {
        if value.is_empty() {
            return Err(InvalidEmail::Empty);
        }
        if value.len() > MAX_EMAIL_BYTES {
            return Err(InvalidEmail::TooLong(value.len()));
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
        if local.contains('@') {
            return Err(InvalidEmail::MultipleSeparators);
        }
        if local.is_empty() {
            return Err(InvalidEmail::EmptyLocalPart);
        }
        if local.len() > MAX_LOCAL_BYTES {
            return Err(InvalidEmail::LocalPartTooLong(local.len()));
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(InvalidEmail::LocalPartDots);
        }
        if domain.is_empty() {
            return Err(InvalidEmail::EmptyDomain);
        }
        // Normalization can lengthen both parts, so limits apply again to the result.
        let local = local.nfc().collect::<String>();
        let domain = domain.nfc().collect::<String>().to_lowercase();
        if local.len() > MAX_LOCAL_BYTES {
            return Err(InvalidEmail::LocalPartTooLong(local.len()));
        }
        let normalized = format!("{local}@{domain}");
        if normalized.len() > MAX_EMAIL_BYTES {
            return Err(InvalidEmail::TooLong(normalized.len()));
        }
        Self::validate_domain(&domain)?;
        Ok(Self(normalized))
    }

    /// Returns the normalized representation used for exact database equality.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// Requires at least two nonempty DNS-style labels without leading or trailing hyphens.
    fn validate_domain(domain: &str) -> Result<(), InvalidEmail> {
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(InvalidEmail::EmptyDomainLabel(domain.into()));
            }
            if label.len() > MAX_DOMAIN_LABEL_BYTES {
                return Err(InvalidEmail::DomainLabelTooLong(label.into()));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(InvalidEmail::DomainLabelHyphen(label.into()));
            }
            if !label
                .chars()
                .all(|character| character.is_alphanumeric() || character == '-')
            {
                return Err(InvalidEmail::DomainLabelCharacter(label.into()));
            }
        }
        if !domain.contains('.') {
            return Err(InvalidEmail::DomainWithoutSuffix(domain.into()));
        }
        Ok(())
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
            ("", InvalidEmail::Empty),
            ("not-an-email", InvalidEmail::MissingSeparator),
            ("a@b@example.com", InvalidEmail::MultipleSeparators),
            ("@example.com", InvalidEmail::EmptyLocalPart),
            ("a..b@example.com", InvalidEmail::LocalPartDots),
            ("a b@example.com", InvalidEmail::ForbiddenCharacter),
            (" a@example.com", InvalidEmail::ForbiddenCharacter),
            ("a@", InvalidEmail::EmptyDomain),
            (
                "a@example..com",
                InvalidEmail::EmptyDomainLabel("example..com".into()),
            ),
            (
                "a@-example.com",
                InvalidEmail::DomainLabelHyphen("-example".into()),
            ),
            (
                "a@exa_mple.com",
                InvalidEmail::DomainLabelCharacter("exa_mple".into()),
            ),
            (
                "a@localhost",
                InvalidEmail::DomainWithoutSuffix("localhost".into()),
            ),
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
            Err(InvalidEmail::LocalPartTooLong(65))
        );
        assert_eq!(
            NormalizedEmail::parse(&format!("a@{}.com", "a".repeat(64))),
            Err(InvalidEmail::DomainLabelTooLong("a".repeat(64)))
        );
    }
}
