//! Transactional internal-event validation.

/// Validates a versioned, credential-free internal-event kind.
pub(super) fn event_kind(value: &str) -> Result<&str, ()> {
    if !value.contains('.')
        || value.len() > 100
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_')
    {
        return Err(());
    }
    Ok(value)
}
