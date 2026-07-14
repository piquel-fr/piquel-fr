//! Conservative email handling policy.

use unicode_normalization::UnicodeNormalization;

/// A normalized email suitable for exact equality checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Returns the database-safe normalized representation.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Normalizes Unicode canonically, lowercases only the domain, and preserves
/// the local part exactly. It intentionally does not remove dots or plus tags.
pub(super) fn normalize(value: &str) -> Result<NormalizedEmail, ()> {
    let value = value.trim();
    if value.is_empty() || value.len() > 254 || value.chars().any(char::is_control) {
        return Err(());
    }
    let (local, domain) = value.rsplit_once('@').ok_or(())?;
    if local.is_empty() || domain.is_empty() || local.len() > 64 || domain.contains('@') {
        return Err(());
    }
    let local = local.nfc().collect::<String>();
    let domain = domain.nfc().collect::<String>().to_lowercase();
    if domain.starts_with('.') || domain.ends_with('.') || !domain.contains('.') {
        return Err(());
    }
    Ok(NormalizedEmail(format!("{local}@{domain}")))
}

#[cfg(test)]
mod tests {
    use super::normalize;
    #[test]
    fn preserves_provider_specific_local_part_semantics() {
        assert_eq!(
            normalize("Ada+jobs@Example.COM")
                .expect("valid normalized email")
                .as_str(),
            "Ada+jobs@example.com"
        );
        assert_ne!(normalize("a.da@example.com"), normalize("ada@example.com"));
    }
    #[test]
    fn rejects_ambiguous_values() {
        assert!(normalize("not-an-email").is_err());
    }
}
