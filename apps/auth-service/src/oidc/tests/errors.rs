//! Standard OAuth error codes and responses (RFC 6749, RFC 6750, RFC 9126): the
//! codes, the challenges and statuses of failed credentials, an optional `state`,
//! and auth's page for a request whose redirect URI isn't verified yet.

use super::*;

/// The scenario's authorization request with `pairs` set, replacing any of the
/// same name, and those named in `removed` left out.
fn request_uri(flow: &Flow, pairs: &[(&str, &str)], removed: &[&str]) -> String {
    let mut url = flow.authorization_url(Scope::OpenId.as_str(), None, &[]);
    let kept: Vec<_> = url
        .query_pairs()
        .into_owned()
        .filter(|(name, _)| {
            !removed.contains(&name.as_str()) && !pairs.iter().any(|(set, _)| set == name)
        })
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(kept)
        .extend_pairs(pairs.iter().copied());
    format!("{}?{}", url.path(), url.query().expect("query"))
}

/// A `response_type` auth doesn't support is `unsupported_response_type`, and a
/// missing one `invalid_request`, both answered on the client's redirect URI.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn response_types_are_refused_with_their_standard_codes() {
    let flow = Flow::new(false, true).await;
    for (pairs, removed, expected) in [
        (
            &[("response_type", "token")][..],
            &[][..],
            OAuthCode::UnsupportedResponseType,
        ),
        (&[][..], &["response_type"][..], OAuthCode::InvalidRequest),
    ] {
        let uri = request_uri(&flow, pairs, removed);
        let response = flow.request(Method::GET, &uri, &[], None).await;
        assert_eq!(
            parameter(&flow.client_redirect(&response), "error"),
            expected.as_str()
        );
    }
}

/// A client without the `state` parameter gets none back, in a code or an error,
/// and a `state` too long to send back fails on auth's page rather than at the
/// client.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn state_is_optional_and_bounded_before_it_goes_back() {
    let flow = Flow::new(false, true).await;
    for pairs in [
        &[][..],
        &[("prompt", "none"), ("scope", "unregistered")][..],
    ] {
        let uri = request_uri(&flow, pairs, &["state"]);
        let response = flow.request(Method::GET, &uri, &[], None).await;
        let redirect = flow.client_redirect(&response);
        assert!(
            redirect.query_pairs().all(|(name, _)| name != "state"),
            "{redirect}"
        );
    }

    let long = "s".repeat(MAX_STATE_BYTES + 1);
    let uri = request_uri(&flow, &[("state", &long), ("response_type", "token")], &[]);
    let response = flow.request(Method::GET, &uri, &[], None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!Flow::text(response).await.contains(&long));
}

/// A pushed request's `request_uri` decides the request: other parameters, even
/// malformed ones, can't fail it. A push names its client with `client_id` even
/// when it authenticates with Basic credentials.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pushed_requests_are_read_before_other_parameters() {
    let flow = Flow::new(true, true).await;
    let request_uri = flow.pushed(Scope::OpenId.as_str(), None).await;
    let response = flow
        .claim(
            flow.client.id.as_str(),
            &request_uri,
            &[("max_age", "garbage")],
        )
        .await;
    assert!(parameter(&flow.client_redirect(&response), "code").starts_with("pac_v1_"));

    let mut url = flow.authorization_url(Scope::OpenId.as_str(), None, &[]);
    let kept: Vec<_> = url
        .query_pairs()
        .into_owned()
        .filter(|(name, _)| name != "client_id")
        .collect();
    url.query_pairs_mut().clear().extend_pairs(kept);
    url.set_path(routes::oidc::PAR);
    let response = flow.post_query(&url, flow.basic.as_deref()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequest.as_str()
    );
}

/// A client is challenged with Basic only when it sent an `Authorization`
/// header; token responses aren't cached by HTTP/1.0 caches either; and a missing
/// `code` or `refresh_token` is a malformed request, not an unusable grant.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn token_endpoint_errors_follow_rfc_6749() {
    let flow = Flow::new(true, true).await;
    let response = flow
        .exchange(
            "pac_v1_unused",
            Flow::verifier(),
            Some("Basic d3Jvbmc6c2VjcmV0"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Basic realm=\"token\""
    );
    let response = flow.exchange("pac_v1_unused", Flow::verifier(), None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));

    let code = flow.code(Scope::OpenId.as_str()).await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");

    for grant in GrantType::ALL {
        let response = flow
            .request(
                Method::POST,
                routes::oidc::TOKEN,
                &[("grant_type", grant.as_str())],
                flow.basic.as_deref(),
            )
            .await;
        assert_eq!(
            Flow::json(response).await["error"],
            OAuthCode::InvalidRequest.as_str(),
            "{grant}"
        );
    }
}

/// An access token without the `openid` scope is refused at `UserInfo` with
/// `insufficient_scope`, at 403, naming the scope it needs.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn userinfo_needs_the_openid_scope() {
    let flow = Flow::new(false, true).await;
    let keys = flow.app.keys.current().expect("keys");
    let token = keys
        .sign(
            TokenType::Access,
            &sourceorigin_common::protocol::claims::AccessTokenClaims {
                iss: flow.app.issuer.clone(),
                sub: flow.user_id.to_string(),
                aud: sourceorigin_common::protocol::claims::Audience::One("api".into()),
                client_id: flow.client.id.clone(),
                jti: sourceorigin_common::TokenId::new(),
                scope: "profile".parse().expect("scopes"),
                iat: Utc::now(),
                exp: Utc::now() + chrono::Duration::minutes(5),
                nbf: None,
                authentication:
                    sourceorigin_common::protocol::claims::AuthenticationClaims::default(),
                act: None,
                cnf: None,
                profile: sourceorigin_common::protocol::claims::ProfileClaims::default(),
                extra: (),
            },
        )
        .expect("access token");
    let bearer = format!("{} {token}", AuthScheme::Bearer);
    let response = flow
        .request(Method::GET, routes::oidc::USERINFO, &[], Some(&bearer))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer error=\"insufficient_scope\", scope=\"openid\""
    );
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InsufficientScope.as_str()
    );
}
