//! Sanitized security-audit policy.

/// Produces a bounded audit action name. Inputs such as tokens and emails are
/// never part of audit metadata or metric labels.
pub(super) fn action(value: &str) -> Result<&str, ()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_')
    {
        return Err(());
    }
    Ok(value)
}
