//! Focused tests for configuration validation and exported vocabulary expansion.
use super::*;

str_enum! {
    /// Test vocabulary proving downstream macro expansion.
    enum Example {
        /// First value.
        First = "first",
        /// Second value.
        Second = "second",
    }
}

/// Closed vocabularies round-trip every spelling and reject unknown values.
#[test]
fn vocabulary_round_trips() {
    assert_eq!(Example::ALL.len(), 2);
    for value in Example::ALL {
        assert_eq!(value.as_str().parse::<Example>(), Ok(value));
        assert_eq!(value.to_string(), value.as_str());
        let json = serde_json::to_string(&value).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Example>(&json).expect("deserialize"),
            value
        );
    }
    assert_eq!(
        "unknown"
            .parse::<Example>()
            .expect_err("unknown")
            .vocabulary,
        "Example"
    );
    assert!(serde_json::from_str::<Example>("\"unknown\"").is_err());
}

/// Public URLs reject every insecure or ambiguous component.
#[test]
fn urls_validate_once() {
    assert!("https://piquel.fr/settings".parse::<PublicUrl>().is_ok());
    assert!("https://auth.piquel.fr".parse::<Origin>().is_ok());
    for value in [
        "http://localhost",
        "https://user@auth.piquel.fr",
        "https://auth.piquel.fr?query",
        "https://auth.piquel.fr#fragment",
        "/relative",
        "https://auth.piquel.fr/path",
    ] {
        assert!(value.parse::<Origin>().is_err(), "accepted {value}");
    }
    assert!("https://[::1]".parse::<Origin>().is_ok());
}

/// References and resolved bytes redact secrets in all diagnostic formatting.
#[test]
fn secrets_are_redacted() {
    let reference = SecretReference::parse("env://AUTH_KEY").expect("reference");
    assert_eq!(format!("{reference:?}"), "SecretReference(REDACTED)");
    assert_eq!(reference.to_string(), "[REDACTED]");
    for value in [
        "env://",
        "file://",
        "https://example.com/key",
        "env://HAS SPACE",
    ] {
        assert!(SecretReference::parse(value).is_err());
    }
    let secret = SecretBytes(b"private".to_vec());
    assert_eq!(secret.utf8().expect("UTF-8"), "private");
    assert!(!format!("{secret:?}").contains("private"));
    assert!(SecretBytes(vec![255]).utf8().is_err());
    let missing = SecretReference::parse("file:///nonexistent/piquel-secret-test")
        .expect("reference")
        .resolve()
        .expect_err("missing file");
    assert!(StdError::source(&missing).is_some());
}

/// Missing variables and parse failures name the setting without exposing its value.
#[test]
fn variable_errors_name_the_setting() {
    let variable = Variable::new("PIQUEL_COMMON_TEST_ABSENT_5A3C");
    assert_eq!(variable.optional().expect("optional"), None);
    assert!(!variable.flag(false).expect("default"));
    assert_eq!(variable.parse_or::<u32>("42").expect("default"), 42);
    assert!(
        variable
            .required()
            .expect_err("absent")
            .to_string()
            .contains(variable.name())
    );
    let source = "not-an-integer".parse::<u32>().expect_err("integer");
    let error = variable.error("must be an integer", source);
    assert!(StdError::source(&error).is_some());
    assert!(!error.to_string().contains("not-an-integer"));
}
