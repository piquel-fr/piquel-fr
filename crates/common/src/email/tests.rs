//! Focused coverage of the conservative equality and rejection policies.
use super::{InvalidEmail, NormalizedEmail};

/// Only the domain's case folds for equality: provider-specific dot and plus
/// equivalence must never merge addresses. The mailbox folds case and plus tags
/// together, for sending limits only.
#[test]
fn equality_is_exact_and_the_mailbox_folds_case_and_plus_tags() {
    let email = |value| NormalizedEmail::parse(value).expect("valid email");
    assert_eq!(
        email("Ada+jobs@Example.COM").as_str(),
        "Ada+jobs@example.com"
    );
    assert_ne!(email("a.da@example.com"), email("ada@example.com"));
    assert_eq!(email("Ada+jobs@Example.COM").mailbox(), "ada@example.com");
    assert_eq!(
        email("ADA@example.com").mailbox(),
        email("ada+1@example.com").mailbox()
    );
    assert_ne!(
        email("a.da@example.com").mailbox(),
        email("ada@example.com").mailbox()
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
