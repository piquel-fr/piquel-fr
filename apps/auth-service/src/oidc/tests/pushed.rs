//! Pushed authorization requests (RFC 9126).

use super::*;

/// A pushed request is validated like a browser one, but answers in JSON. Its
/// `request_uri` is not a transaction: only its client can claim it, once, and the
/// query cannot override what was pushed, `prompt` included. A client required to
/// push cannot send plain requests.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pushed_requests_are_one_time_client_bound_and_authoritative() {
    let mut flow = Flow::new(true, false).await;
    let id = flow.client.id.to_string();
    let response = flow.push(Scope::OpenId.as_str(), None, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidClient.as_str()
    );
    let response = flow
        .push("openid unregistered", None, flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidScope.as_str()
    );
    let request_uri = flow
        .pushed(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.claim(&id, &request_uri, &[]).await),
            "error"
        ),
        OAuthCode::ConsentRequired.as_str()
    );
    let request_uri = flow.pushed(Scope::OpenId.as_str(), None).await;
    let transaction = request_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .expect("RFC 9126 request_uri");
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // No redirect URI is known for a request_uri that can't be claimed, so auth's
    // page explains it.
    let rejected = async |client_id: &str, request_uri: &str| {
        let response = flow.claim(client_id, request_uri, &[]).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let page = Flow::text(response).await;
        assert!(
            page.contains("request_uri is unknown, expired, already used or issued to another")
                || page.contains("request_uri must come from the pushed authorization endpoint"),
            "{page}"
        );
    };
    let other = crate::tests::registration(ClientKind::Public, "https://other.example");
    crate::tests::register(&flow.app.database, &other)
        .await
        .expect("register another client");
    rejected(other.id.as_str(), &request_uri).await;
    rejected(&id, "urn:ietf:params:oauth:request_uri:unknown").await;
    rejected(&id, "https://client.example/request.jwt").await;
    let response = flow
        .claim(
            &id,
            &request_uri,
            &[
                ("scope", EMAIL_SCOPES),
                ("state", "forged-state"),
                ("redirect_uri", "https://evil.example/callback"),
                ("prompt", Prompt::None.as_str()),
            ],
        )
        .await;
    let redirect = flow.consent(response).await;
    assert_eq!(
        redirect.origin(),
        Url::parse(flow.client.redirect_uris[0].as_str())
            .expect("callback")
            .origin()
    );
    assert_eq!(parameter(&redirect, "state"), "test-state");
    let code = parameter(&redirect, "code");
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    let (tokens, claims) = flow.id_token(response).await;
    assert_eq!(tokens["scope"], Scope::OpenId.as_str());
    assert_eq!(claims["nonce"], "test-nonce");
    rejected(&id, &request_uri).await;
    flow.client.require_pushed_authorization_requests = true;
    let client = flow.client.clone();
    crate::tests::replace(&flow.app.database, &client)
        .await
        .expect("require pushed requests");
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.authorize(Scope::OpenId.as_str(), None).await),
            "error"
        ),
        OAuthCode::UnauthorizedClient.as_str()
    );
    let request_uri = flow.pushed(Scope::OpenId.as_str(), None).await;
    // The user consented above, so the claim returns a code at once.
    let response = flow.claim(&id, &request_uri, &[]).await;
    parameter(&flow.client_redirect(&response), "code");
}

/// A pushed `prompt=login` needs a sign-in after the browser claims the request:
/// one between the push and the claim is not fresh.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pushed_requests_count_sign_in_freshness_from_the_claim() {
    let mut flow = Flow::new(true, false).await;
    let request_uri = flow
        .pushed(Scope::OpenId.as_str(), Some(Prompt::Login.as_str()))
        .await;
    flow.sign_in_again(AuthenticationMethod::Passkey).await;
    let response = flow.claim(flow.client.id.as_str(), &request_uri, &[]).await;
    let location = location(&response);
    assert_eq!(location.path(), "/login");
    let transaction = parameter(&location, "transaction");
    flow.sign_in_again(AuthenticationMethod::Passkey).await;
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    parameter(&flow.consent(response).await, "code");
}
