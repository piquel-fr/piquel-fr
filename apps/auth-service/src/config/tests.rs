//! Audit key validation, and the configuration reference.

use super::*;
use piquel_common::config::{GeneratedFile, Section};

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

/// The configuration reference's auth-service sections say what these modules
/// declare. `just docs reference` rewrites them.
#[test]
fn configuration_reference_is_current() {
    let sections = [
        Section {
            title: "Service",
            variables: VARIABLES,
        },
        Section {
            title: "Database",
            variables: database::VARIABLES,
        },
        Section {
            title: "Keys",
            variables: keys::VARIABLES,
        },
        Section {
            title: "Sign-in providers",
            variables: federation::VARIABLES,
        },
        Section {
            title: "Email",
            variables: email::VARIABLES,
        },
    ];
    GeneratedFile {
        path: concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/dev/operations/variables/auth-service.md"
        )
        .into(),
        text: Section::render(&sections, 3, "the variables in `apps/auth-service/src/config`"),
    }
    .write_or_compare()
    .expect("current reference");
}
