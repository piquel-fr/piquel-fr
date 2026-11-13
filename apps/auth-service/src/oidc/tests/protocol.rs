//! Discovery metadata, POST parity, OAuth error formats and protocol parsing.

use super::*;

/// Both well-known paths serve the same cacheable, typed document, and every endpoint
/// it advertises is routed on the issuer.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn metadata_is_one_document_whose_endpoints_are_routed() {
    let flow = Flow::new(false, false).await;
    let mut documents = vec![];
    let jwks = flow
        .request(Method::GET, routes::oidc::JWKS, &[], None)
        .await;
    assert_eq!(
        jwks.extensions().get::<CacheClass>(),
        Some(&PublicDocument::CACHE)
    );
    for path in [routes::oidc::DISCOVERY, routes::oidc::OAUTH_METADATA] {
        let response = flow.request(Method::GET, path, &[], None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.extensions().get::<CacheClass>(),
            Some(&PublicDocument::CACHE)
        );
        documents.push(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read metadata"),
        );
    }
    assert_eq!(documents[0], documents[1]);
    let metadata: ServerMetadata = serde_json::from_slice(&documents[0]).expect("typed metadata");
    assert_eq!(metadata.issuer, flow.app.issuer);
    assert_eq!(metadata.acr_values_supported, Acr::ALL);
    let Value::Object(fields) = serde_json::from_slice(&documents[0]).expect("metadata JSON")
    else {
        panic!("metadata is not a JSON object");
    };
    for (name, value) in fields {
        if !(name.ends_with("_endpoint") || name == "jwks_uri") {
            continue;
        }
        let url = Url::parse(value.as_str().expect("endpoint text")).expect("endpoint URL");
        assert_eq!(
            url.origin().ascii_serialization(),
            metadata.issuer,
            "{name}"
        );
        let response = flow.request(Method::GET, url.path(), &[], None).await;
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "{name}");
    }
}

/// Checks protocol POST parity and existing OAuth error and challenge formats.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn post_protocol_endpoints_and_error_contracts() {
    let flow = Flow::new(false, true).await;
    for (name, value, expected) in [
        (
            "id_token_hint",
            "invalid",
            OAuthCode::InvalidRequest.as_str(),
        ),
        (
            "request",
            "ignored.jwt",
            OAuthCode::RequestNotSupported.as_str(),
        ),
        (
            "response_mode",
            "form_post",
            OAuthCode::InvalidRequest.as_str(),
        ),
    ] {
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[(name, value)],
            )
            .await;
        assert_eq!(
            parameter(&flow.client_redirect(&response), "error"),
            expected
        );
    }
    let discovery = Flow::json(
        flow.request(Method::GET, "/.well-known/openid-configuration", &[], None)
            .await,
    )
    .await;
    assert_eq!(discovery["request_parameter_supported"], false);
    assert_eq!(discovery["request_uri_parameter_supported"], false);
    assert_eq!(
        discovery["pushed_authorization_request_endpoint"],
        format!("{}{}", flow.app.issuer, routes::oidc::PAR)
    );
    // Only pushed requests have a request_uri, and no redirect URI is known for it.
    let response = flow
        .claim(
            flow.client.id.as_str(),
            "https://example.com/request.jwt",
            &[],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequestUri.as_str()
    );
    assert_eq!(
        discovery["authorization_response_iss_parameter_supported"],
        true
    );
    let response = flow
        .authorize_with(Method::POST, PROFILE_SCOPES, None, &[])
        .await;
    let code = parameter(&flow.client_redirect(&response), "code");
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    let bearer = format!(
        "{} {}",
        AuthScheme::Bearer.as_str(),
        tokens["access_token"].as_str().expect("access token")
    );
    let response = flow
        .request(Method::POST, "/oidc/userinfo", &[], Some(&bearer))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo = Flow::json(response).await;
    assert_eq!(userinfo["sub"], json!(flow.user_id));
    assert!(userinfo["profile_version"].is_number());
    let response = flow
        .request(Method::POST, "/oidc/userinfo", &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer error=\"invalid_token\""
    );
    let response = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[("client_id", flow.client.id.as_str())],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequest.as_str()
    );
}

/// Checks case-insensitive scheme matching without changing credential bytes.
#[test]
fn authentication_schemes_are_case_insensitive() {
    assert_eq!(AuthScheme::Bearer.credentials("bEaReR a.B"), Some("a.B"));
    assert_eq!(AuthScheme::Basic.credentials("BASIC Zm9v"), Some("Zm9v"));
    assert_eq!(AuthScheme::Basic.credentials("Bearer Zm9v"), None);
    assert_eq!(AuthScheme::Bearer.credentials("Bearer"), None);
}

/// Checks deduplication, lexical ordering and preservation of registered extension scopes.
#[test]
fn scope_sets_preserve_existing_wire_semantics() {
    let scopes = Scopes::parse("profile openid profile custom.read email").expect("scope set");
    assert!(scopes.contains(Scope::OpenId));
    assert_eq!(
        scopes.wire().to_string(),
        "custom.read email openid profile"
    );
    let stored = scopes.clone().into_stored();
    assert!(scopes.allowed_by(&stored));
    assert!(!scopes.allowed_by(&[Scope::OpenId.as_str().into()]));
    assert_eq!(Scopes::from_stored(&stored), Ok(scopes));
    assert!(Scopes::parse(" ").is_err());
    let too_many = (0..=MAX_SCOPES)
        .map(|index| format!("scope{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(Scopes::parse(&too_many).is_err());
}

/// Checks purpose binding, the length bound and exact opaque envelope/secret round
/// trips.
#[test]
fn opaque_tokens_preserve_envelopes_and_reject_wrong_purpose() {
    let huge = format!(
        "{}_{}.{:0200}",
        TokenPrefix::RefreshToken,
        TokenId::new(),
        "x"
    );
    assert!(OpaqueToken::parse(TokenPrefix::RefreshToken, &huge).is_err());
    for prefix in TokenPrefix::ALL {
        let original = OpaqueToken::new(prefix).expect("random token");
        let encoded = original.encoded();
        let parsed = OpaqueToken::parse(prefix, &encoded).expect("parse envelope");
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.secret.as_bytes(), original.secret.as_bytes());
        assert_eq!(parsed.encoded(), encoded);
        for other in TokenPrefix::ALL {
            if prefix != other {
                assert!(OpaqueToken::parse(other, &encoded).is_err());
            }
        }
    }
}

/// Checks that protocol failures retain both internal and rejected-input source
/// chains. A rejection's description is what a browser navigating to it, as to the
/// authorization endpoint, reads on its error page.
#[tokio::test]
async fn oauth_failures_preserve_sources_and_statuses() {
    use crate::security::Explanation;
    use axum::response::IntoResponse;
    use std::error::Error;
    let error = OAuthError::from(sourceorigin_repository::DatabaseError::Operation(Box::new(
        std::io::Error::other("internal diagnostic"),
    )));
    assert_eq!(
        error.source().expect("internal source").to_string(),
        "internal diagnostic"
    );
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let error = OAuthCode::InvalidGrant.reject_with(
        "code is \"malformed\" \u{2014} retry",
        sourceorigin_crypto::CryptoError::SecretLength,
    );
    assert!(error.source().is_some());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<Explanation>()
            .map(|shown| shown.0.as_str()),
        Some("The app's request was refused: code is \"malformed\" \u{2014} retry.")
    );
    // The description reaches the client, restricted to the RFC 6749 character set.
    assert_eq!(
        Flow::json(response).await,
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "code is 'malformed' ? retry",
        })
    );
}
