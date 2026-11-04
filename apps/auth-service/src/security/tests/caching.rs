//! The `Cache-Control` and CORS headers cached responses carry.

use super::*;

/// Decorates `response` as [`HttpSecurity::protect`] does on the given CORS `grant`.
fn decorated(response: impl IntoResponse, grant: Option<CorsGrant>) -> Response {
    let mut response = response.into_response();
    HttpSecurity::decorate(&mut response, grant);
    response
}

/// The CORS grant of an approved origin, such as a public client's.
fn client() -> CorsGrant {
    CorsGrant::Client(HeaderValue::from_static("https://external.example"))
}

/// Each class sends its own `Cache-Control`.
#[test]
fn cached_responses_carry_their_class() {
    for (class, cache_control) in [
        (
            CacheClass::Immutable,
            "public, max-age=31536000, immutable, no-transform",
        ),
        (
            CacheClass::Public {
                max_age: std::time::Duration::from_secs(3600),
            },
            "public, max-age=3600, no-transform",
        ),
    ] {
        let response = decorated(Cached(class, StatusCode::OK), None);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            cache_control,
            "{class:?}"
        );
    }
}

/// Only a classed success without cookies may be stored: anything
/// else is `no-store`, whatever the handler set.
#[test]
fn unclassed_errors_and_cookie_responses_are_not_stored() {
    let class = CacheClass::Public {
        max_age: std::time::Duration::from_secs(3600),
    };
    for response in [
        decorated(Cached(class, [(header::SET_COOKIE, "a=b")]), None),
        decorated(Cached(class, StatusCode::FORBIDDEN), None),
        decorated(Cached(class, StatusCode::NOT_FOUND), None),
        decorated(Cached(class, StatusCode::TOO_MANY_REQUESTS), None),
        decorated([(header::CACHE_CONTROL, "public, max-age=60")], None),
    ] {
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, no-transform"
        );
    }
}

/// Public data is readable from every origin without credentials, so one cached copy
/// serves them all; an embedded file has no CORS headers, even for an approved
/// origin.
#[test]
fn cached_responses_are_the_same_for_every_origin() {
    let public = CacheClass::Public {
        max_age: std::time::Duration::from_secs(3600),
    };
    for grant in [None, Some(client())] {
        let response = decorated(Cached(public, StatusCode::OK), grant);
        let headers = response.headers();
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert!(!headers.contains_key(header::VARY));
    }
    let response = decorated(
        Cached(CacheClass::Immutable, StatusCode::OK),
        Some(client()),
    );
    let headers = response.headers();
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
    assert!(!headers.contains_key(header::VARY));
}
