//! Syntax and reservation vectors.
use super::{Handle, HandleError};

/// Input is trimmed and lowercased, then must be a 3–32 character DNS label.
#[test]
fn parse_vectors() {
    let longest = "x".repeat(32);
    let too_long = "x".repeat(33);
    let accepted = [
        ("abc", "abc"),
        ("  Alice  ", "alice"),
        ("ALICE-b0b", "alice-b0b"),
        ("a-b-c", "a-b-c"),
        ("123", "123"),
        (&longest, &longest),
    ];
    for (input, handle) in accepted {
        assert_eq!(
            Handle::parse(input).map(String::from).as_deref(),
            Ok(handle),
            "{input:?}"
        );
    }
    let rejected = [
        ("ab", HandleError::Length),
        ("  ab  ", HandleError::Length),
        (&too_long, HandleError::Length),
        ("ééé", HandleError::Charset),
        ("a_b", HandleError::Charset),
        ("a.b", HandleError::Charset),
        ("a b", HandleError::Charset),
        ("-ab", HandleError::Charset),
        ("ab-", HandleError::Charset),
        ("a--b", HandleError::Charset),
        ("xn--bcher-kva", HandleError::Charset),
    ];
    for (input, error) in rejected {
        assert_eq!(Handle::parse(input), Err(error), "{input:?}");
    }
}

/// Stored and wire handles must already be canonical.
#[test]
fn decoding_is_strict() {
    assert_eq!(
        "alice".parse::<Handle>().map(String::from),
        Ok("alice".into())
    );
    for input in ["Alice", " alice", "a_b"] {
        assert!(input.parse::<Handle>().is_err(), "{input:?}");
        assert!(
            serde_json::from_value::<Handle>(serde_json::json!(input)).is_err(),
            "{input:?}"
        );
    }
}
