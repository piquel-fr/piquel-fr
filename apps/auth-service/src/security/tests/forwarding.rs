//! Which peers may supply a forwarded client address, and how it is parsed.

use super::*;

/// Only configured ingress peers may supply a single forwarded client address.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn forwarded_addresses_require_an_explicit_trusted_peer() {
    let mut fixture = SecurityFixture::new().await;
    let mut request = HttpRequest::builder()
        .header("x-forwarded-for", "192.0.2.7")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(fixture.peer));
    assert_eq!(
        fixture.policy.client_ip(&request).expect("direct peer"),
        fixture.peer.ip()
    );
    fixture.policy.trusted_proxies = Arc::new(vec![IpNet::from(fixture.peer.ip())]);
    assert_eq!(
        fixture.policy.client_ip(&request).expect("trusted header"),
        "192.0.2.7".parse::<IpAddr>().expect("IP")
    );
    request
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("192.0.2.8"));
    assert!(fixture.policy.client_ip(&request).is_err());
    request.headers_mut().remove("x-forwarded-for");
    assert!(fixture.policy.client_ip(&request).is_err());
    request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("192.0.2.7, 192.0.2.8"),
    );
    assert!(fixture.policy.client_ip(&request).is_err());
}

/// Forwarded addresses accept one IP and retain diagnostics for malformed header text or syntax.
#[test]
fn forwarded_address_parser_requires_one_address_and_preserves_causes() {
    let mut headers = HeaderMap::new();
    assert!(matches!(
        HttpSecurity::forwarded_ip(&headers),
        Err(HttpSecurityError::MissingForwardedAddress)
    ));
    for valid in ["192.0.2.7", "2001:db8::7"] {
        headers.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_str(valid).expect("header"),
        );
        assert_eq!(
            HttpSecurity::forwarded_ip(&headers).expect("forwarded address"),
            valid.parse::<IpAddr>().expect("IP")
        );
    }
    headers.append(FORWARDED_FOR_HEADER, HeaderValue::from_static("192.0.2.8"));
    assert!(matches!(
        HttpSecurity::forwarded_ip(&headers),
        Err(HttpSecurityError::MultipleForwardedHeaders)
    ));
    headers.insert(
        FORWARDED_FOR_HEADER,
        HeaderValue::from_static("192.0.2.7, 192.0.2.8"),
    );
    let error = HttpSecurity::forwarded_ip(&headers).expect_err("one address required");
    assert!(matches!(error, HttpSecurityError::ForwardedAddress(_)));
    assert!(std::error::Error::source(&error).is_some());
    headers.insert(
        FORWARDED_FOR_HEADER,
        HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
    );
    let error = HttpSecurity::forwarded_ip(&headers).expect_err("HTTP text required");
    assert!(matches!(error, HttpSecurityError::ForwardedHeader(_)));
    assert!(std::error::Error::source(&error).is_some());
}
