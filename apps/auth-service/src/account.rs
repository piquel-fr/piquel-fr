//! Account policy boundaries; persistence is delegated to the repository crate.

use piquel_auth_protocol::{AccountStatus, UserId};

/// Validated account profile snapshot used by the identity service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AccountProfile {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub version: u64,
    pub status: AccountStatus,
}

/// Checks the deliberately narrow username policy used for initial accounts.
pub(super) fn validate_username(value: &str) -> Result<(), ()> {
    if !(3..=32).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(());
    }
    Ok(())
}
/// Checks a presentation name without treating it as an identity key.
pub(super) fn validate_display_name(value: &str) -> Result<(), ()> {
    if value.trim().is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_validation_is_deliberate() {
        assert!(validate_username("ada_lovelace").is_ok());
        assert!(validate_username("Ada").is_err());
        assert!(validate_display_name("Ada Lovelace").is_ok());
    }
}
