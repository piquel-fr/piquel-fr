//! Audit key validation.

use super::*;

/// The audit key is a 32-byte seed in hex, with one trailing newline allowed.
/// Anything else stops startup with an error naming the variable.
#[test]
fn audit_keys_must_be_32_hex_encoded_bytes() {
    let origin: Origin = "https://auth.piquel.fr".parse().expect("origin");
    let path = std::env::temp_dir().join(format!("audit-key-{}", piquel_common::UserId::new()));
    let parse = |value: &str| {
        std::fs::write(&path, value).expect("secret file");
        let secret = SecretReference::parse(&format!("file://{}", path.display()))
            .and_then(|reference| reference.resolve())
            .expect("secret");
        AuditConfig::parse(&origin, &secret)
    };
    let config = parse(&format!("{}\n", "ab".repeat(32))).expect("generated secret");
    assert_eq!(config.verifier().name(), "auth.piquel.fr/audit");
    for malformed in [
        "ab".repeat(31),
        "ab".repeat(33),
        "zz".repeat(32),
        "-----BEGIN".into(),
    ] {
        let error = parse(&malformed).err().expect("malformed key").to_string();
        assert!(error.contains("AUTH_AUDIT_KEY_PROVIDER"), "{error}");
        assert!(error.contains("64 hexadecimal characters"), "{error}");
    }
    std::fs::remove_file(path).expect("cleanup");
}
