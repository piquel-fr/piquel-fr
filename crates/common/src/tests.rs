//! Focused tests for exported vocabulary expansion and identifier syntax.
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

open_str_enum! {
    /// Test vocabulary proving open-vocabulary expansion.
    enum OpenExample {
        /// Known value.
        Known = "known",
    }
}

/// Open vocabularies parse known spellings to variants and keep others verbatim.
#[test]
fn open_vocabulary_keeps_unknown_values() {
    assert_eq!(OpenExample::from("known"), OpenExample::Known);
    let other: OpenExample = serde_json::from_str("\"later\"").expect("deserialize");
    assert_eq!(other, OpenExample::Other("later".into()));
    assert_eq!(
        serde_json::to_string(&other).expect("serialize"),
        "\"later\""
    );
    assert_eq!(OpenExample::KNOWN.len(), 1);
}

/// IDs accept only canonical `UUIDv7`, preserving syntax diagnostics on malformed text.
#[test]
fn ids_are_canonical_uuid_v7() {
    let id = UserId::new();
    assert_eq!(id.to_string().parse::<UserId>(), Ok(id));
    assert!(
        "00000000-0000-4000-8000-000000000000"
            .parse::<UserId>()
            .is_err()
    );
    assert!(id.to_string().to_uppercase().parse::<UserId>().is_err());
    let error = "not-a-uuid".parse::<UserId>().expect_err("UUID syntax");
    assert!(std::error::Error::source(&error).is_some());
}
