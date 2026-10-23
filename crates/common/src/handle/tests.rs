//! Syntax, reservation and skeleton vectors.
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

/// Look-alikes share a skeleton; distinct names do not.
#[test]
fn skeleton_vectors() {
    let skeleton = |handle: &str| Handle::parse(handle).expect("valid").skeleton();
    for (left, right) in [
        ("pique1", "piquel"),
        ("p-iquel", "piquel"),
        ("rnoon", "moon"),
        ("vvave", "wave"),
        ("b0b", "bob"),
        ("5am", "sam"),
        ("adm1n", "admin"),
    ] {
        assert_eq!(skeleton(left), skeleton(right), "{left} / {right}");
    }
    assert_eq!(skeleton("rn-0-1i5-vv"), "mollsw");
    assert_ne!(skeleton("alice"), skeleton("alicia"));
}

/// Reserved names and their confusables are refused; other names are not.
#[test]
fn reserved_names() {
    let reserved = |handle: &str| Handle::parse(handle).expect("valid").ensure_unreserved();
    for (handle, name) in [
        ("admin", "admin"),
        ("adm1n", "admin"),
        ("pique1", "piquel"),
        ("p-iquel", "piquel"),
        ("postmaster", "postmaster"),
        ("www", "www"),
    ] {
        assert_eq!(
            reserved(handle),
            Err(HandleError::Reserved(name.into())),
            "{handle}"
        );
    }
    for handle in ["alice", "admins", "piquel-fan"] {
        assert_eq!(reserved(handle), Ok(()), "{handle}");
    }
}
