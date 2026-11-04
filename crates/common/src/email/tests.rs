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

/// Case and plus tags of one mailbox fold together for sending limits only.
#[test]
fn mailbox_folds_case_and_plus_tags() {
    let mailbox = |value| {
        NormalizedEmail::parse(value)
            .expect("valid email")
            .mailbox()
    };
    assert_eq!(mailbox("Ada+jobs@Example.COM"), "ada@example.com");
    assert_eq!(mailbox("ADA@example.com"), mailbox("ada+1@example.com"));
    assert_ne!(mailbox("a.da@example.com"), mailbox("ada@example.com"));
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
