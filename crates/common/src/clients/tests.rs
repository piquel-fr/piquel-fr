//! Each registration field's rules at their bounds, and the errors naming them.
use super::*;

/// Client IDs accept the identifier alphabet up to 64 bytes, and serde enforces it.
#[test]
fn client_ids_are_bounded_identifiers() {
    for (value, valid) in [
        ("", false),
        ("has space", false),
        ("a._-Z09", true),
        (&"x".repeat(64), true),
        (&"x".repeat(65), false),
        ("é", false),
    ] {
        assert_eq!(value.parse::<ClientId>().is_ok(), valid, "{value}");
    }
    assert!(serde_json::from_str::<ClientId>("\"bad id\"").is_err());
    assert_eq!(
        "bad id".parse::<ClientId>().expect_err("space").to_string(),
        "client ID \"bad id\" must be 1 to 64 characters from A-Z, a-z, 0-9, '.', '_' and '-'"
    );
}

/// Redirect URIs need HTTPS, or HTTP on a loopback IP, without credentials,
/// fragments or a form that differs from what clients would send.
#[test]
fn redirect_uris_follow_the_transport_and_exact_match_rules() {
    for valid in [
        "https://app.example/callback?flow=one",
        "https://app.example:8443/",
        "http://127.0.0.1:8080/callback",
        "http://[::1]/callback",
    ] {
        assert_eq!(
            valid
                .parse::<RedirectUri>()
                .map(|uri| uri.to_string())
                .as_deref(),
            Ok(valid)
        );
    }
    assert_eq!(
        "http://example.com/cb"
            .parse::<RedirectUri>()
            .expect_err("http")
            .to_string(),
        "redirect URI http://example.com/cb must use https; http is allowed only on a \
         loopback IP, e.g. http://127.0.0.1:8080/callback"
    );
    for (value, expected) in [
        (
            "http://localhost/cb",
            InvalidRedirectUri::Insecure {
                uri: "http://localhost/cb".into(),
            },
        ),
        (
            "app://callback",
            InvalidRedirectUri::Insecure {
                uri: "app://callback".into(),
            },
        ),
        (
            "https://user:pw@app.example/",
            InvalidRedirectUri::Credentials,
        ),
        (
            "https://app.example/#done",
            InvalidRedirectUri::Fragment {
                uri: "https://app.example/#done".into(),
            },
        ),
        (
            "https://APP.example",
            InvalidRedirectUri::NotCanonical {
                uri: "https://APP.example".into(),
                canonical: "https://app.example/".into(),
            },
        ),
    ] {
        assert_eq!(value.parse::<RedirectUri>(), Err(expected), "{value}");
    }
    let error = "/relative".parse::<RedirectUri>().expect_err("relative");
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(
        "https://app.example:8443/cb"
            .parse::<RedirectUri>()
            .map(|uri| uri.origin()),
        Ok("https://app.example:8443".into())
    );
}

/// Display names are nonblank and count characters, not bytes; scopes are tokens.
#[test]
fn names_and_scopes_are_bounded() {
    assert!("é".repeat(80).parse::<DisplayName>().is_ok());
    assert!("é".repeat(81).parse::<DisplayName>().is_err());
    assert!("  ".parse::<DisplayName>().is_err());
    for (value, valid) in [
        ("notes:read", true),
        ("", false),
        ("two words", false),
        (&"s".repeat(64), true),
        (&"s".repeat(65), false),
    ] {
        assert_eq!(value.parse::<ScopeName>().is_ok(), valid, "{value}");
    }
}

/// Bounded lists drop repeats before counting them.
#[test]
fn bounded_lists_count_distinct_values() {
    let scopes = AllowedScopes::new([Scope::OpenId, Scope::OpenId].map(ScopeName::from))
        .expect("one distinct scope");
    assert_eq!(scopes.len(), 1);
    assert_eq!(
        RedirectUris::new([]),
        Err(InvalidCount {
            min: 1,
            max: 16,
            found: 0
        })
    );
    assert!(PostLogoutUris::new([]).is_ok());
}
