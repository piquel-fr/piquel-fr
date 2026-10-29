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

/// Related origins are HTTPS domain origins, written as browsers send them.
#[test]
fn related_origins_are_bare_https_domain_origins() {
    for valid in ["https://notes.example", "https://notes.example:8443"] {
        let origin: RelatedOrigin = valid.parse().expect(valid);
        assert_eq!(origin.as_str(), valid);
        assert_eq!(origin.host(), "notes.example");
    }
    for (value, expected) in [
        (
            "http://notes.example",
            InvalidRelatedOrigin::Insecure {
                origin: "http://notes.example".into(),
            },
        ),
        (
            "https://127.0.0.1",
            InvalidRelatedOrigin::Insecure {
                origin: "https://127.0.0.1".into(),
            },
        ),
        (
            "https://user@notes.example",
            InvalidRelatedOrigin::Credentials,
        ),
        (
            "https://notes.example/app",
            InvalidRelatedOrigin::NotCanonical {
                origin: "https://notes.example/app".into(),
                canonical: "https://notes.example".into(),
            },
        ),
        (
            "https://Notes.example:443",
            InvalidRelatedOrigin::NotCanonical {
                origin: "https://Notes.example:443".into(),
                canonical: "https://notes.example".into(),
            },
        ),
    ] {
        assert_eq!(value.parse::<RelatedOrigin>(), Err(expected), "{value}");
    }
    assert!(serde_json::from_str::<RelatedOrigin>("\"https://notes.example/\"").is_err());
}

/// Display names are nonblank and count characters, not bytes; scopes are tokens.
#[test]
fn names_and_scopes_are_bounded() {
    assert!("é".repeat(80).parse::<DisplayName>().is_ok());
    assert!("é".repeat(81).parse::<DisplayName>().is_err());
    assert!("  ".parse::<DisplayName>().is_err());
    assert!("Web\x1b[2J".parse::<DisplayName>().is_err());
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

/// Generated client IDs are valid IDs with the `c_` prefix and 20 base32
/// characters, and differ with their random input.
#[test]
fn generated_client_ids_use_the_prefix_and_base32() {
    let id = ClientId::generated(&[0xff; 32]);
    assert_eq!(id.as_str(), format!("c_{}", "7".repeat(20)));
    assert_eq!(id.as_str().parse::<ClientId>(), Ok(id.clone()));
    let mut random = [0; 32];
    random[19] = 1;
    assert_eq!(
        ClientId::generated(&random).as_str(),
        format!("c_{}b", "a".repeat(19))
    );
}
