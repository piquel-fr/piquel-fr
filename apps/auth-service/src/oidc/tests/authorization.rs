//! Authorization requests: consent, PKCE, scoped claims and account hints.

use super::*;
use sourceorigin_repository::SessionScope;

/// Checks public-client consent, PKCE, scoped claims and one-use authorization codes:
/// a redemption with the wrong verifier expires its code, so it cannot be tried
/// again.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn public_consent_pkce_claim_scoping_and_replay() {
    let flow = Flow::new(false, false).await;
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
    let burned = flow.code(Scope::OpenId.as_str()).await;
    for verifier in ["wrong", Flow::verifier()] {
        assert_eq!(
            flow.exchange(&burned, verifier, None).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let code = flow.code(Scope::OpenId.as_str()).await;
    let response = flow.exchange(&code, Flow::verifier(), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims: IdTokenClaims = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify scoped ID token");
    assert_eq!(claims.nonce.as_deref(), Some("test-nonce"));
    assert!(claims.profile.name.is_none());
    assert!(claims.profile.email.is_none());
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert!(
        flow.client_redirect(&response)
            .query_pairs()
            .any(|(name, _)| name == "code")
    );
    let response = flow
        .authorize(EMAIL_SCOPES, Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::Login.as_str()))
        .await;
    assert_eq!(location(&response).path(), "/login");
    let client_id = flow.client.id.clone();
    assert_eq!(
        flow.events().await[..4],
        [
            DomainEvent::CodeReplayed {
                client_id: client_id.clone(),
            },
            DomainEvent::GrantIssued {
                client_id: client_id.clone(),
                family_id: None,
                scopes: vec![Scope::OpenId.as_str().into()],
            },
            DomainEvent::CodeRedemptionFailed {
                client_id: client_id.clone(),
                reason: CodeRedemptionFailure::InvalidVerifier,
            },
            DomainEvent::ConsentGranted {
                client_id,
                scopes: vec![Scope::OpenId.as_str().into()],
            },
        ]
    );
}

/// A failed redemption uses its code up even for a redemption already waiting on
/// it: both wait on the account, the failed one decides the code first, and the
/// valid one then finds it expired.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_failed_redemption_uses_the_code_up_for_one_waiting() {
    let flow = Flow::new(false, false).await;
    let code = flow.code(Scope::OpenId.as_str()).await;
    let database = flow.app.database.clone();
    let mut holder = database.begin().await.expect("transaction");
    holder
        .users()
        .find_active_by_id_for_update(flow.user_id)
        .await
        .expect("lock")
        .expect("account");
    let exchange = |verifier: &'static str| {
        let (flow, code) = (flow.clone(), code.clone());
        tokio::spawn(async move { flow.exchange(&code, verifier, None).await.status() })
    };
    let failed = exchange("wrong");
    until_blocked(&mut holder, 1).await;
    let valid = exchange(Flow::verifier());
    until_blocked(&mut holder, 2).await;
    holder.commit().await.expect("commit");

    assert_eq!(failed.await.expect("failed"), StatusCode::BAD_REQUEST);
    assert_eq!(valid.await.expect("valid"), StatusCode::BAD_REQUEST);
    let events = flow.events().await;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, DomainEvent::GrantIssued { .. })),
        "{events:?}"
    );
}

/// Checks that ID hints bind the account across initial, resumed and consent requests.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authorization_hints_bind_initial_resumed_and_consent_requests() {
    let flow = Flow::new(false, true).await;
    let now = Utc::now().timestamp();
    let claims = json!({"iss":flow.app.issuer,"sub":flow.user_id,"aud":flow.client.id,"iat":now-600,"exp":now-300});
    let hint = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .sign(TokenType::Id, &claims)
        .expect("sign expired hint");
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert_ne!(parameter(&flow.client_redirect(&response), "code"), "");
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!("other-client")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        let hint = flow
            .app
            .keys
            .current()
            .expect("fresh keys")
            .sign(TokenType::Id, &invalid)
            .expect("sign invalid hint");
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[("id_token_hint", &hint)],
            )
            .await;
        assert_eq!(
            parameter(&flow.client_redirect(&response), "error"),
            OAuthCode::InvalidRequest.as_str()
        );
    }
    let mut other = claims;
    other["sub"] = json!(UserId::new());
    let hint = flow
        .app
        .keys
        .current()
        .expect("fresh keys")
        .sign(TokenType::Id, &other)
        .expect("sign other account hint");
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::LoginRequired.as_str()
    );
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            None,
            &[("id_token_hint", &hint)],
        )
        .await;
    let login = location(&response);
    assert_eq!(login.path(), "/login");
    let transaction = parameter(&login, "transaction");
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    assert_eq!(location(&response).path(), "/login");
    let response = flow
        .request(
            Method::POST,
            routes::page::CONSENT,
            &[("transaction", &transaction), ("decision", APPROVE_CONSENT)],
            None,
        )
        .await;
    // A page refusing the browser's session challenges no scheme, so it isn't 401.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A consent that waits for the account lock while every session ends is not
/// saved: approving reads the session again under the lock.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_consent_whose_session_ended_while_waiting_is_not_saved() {
    let flow = Flow::new(true, false).await;
    let response = flow.authorize("openid", None).await;
    let transaction = parameter(&location(&response), "transaction");
    let database = flow.app.database.clone();
    let mut holder = database.begin().await.expect("transaction");
    holder
        .users()
        .find_active_by_id_for_update(flow.user_id)
        .await
        .expect("lock")
        .expect("user");
    let approving = flow.clone();
    let decision = tokio::spawn(async move {
        let form = [
            ("transaction", transaction.as_str()),
            ("decision", APPROVE_CONSENT),
        ];
        let response = approving
            .request(Method::POST, routes::page::CONSENT, &form, None)
            .await;
        response.status()
    });
    until_blocked(&mut holder, 1).await;
    let context = RequestContext::TEST.actor(Actor::Anonymous);
    holder
        .revoke_sessions(
            &context,
            flow.user_id,
            SessionScope::All,
            &RevocationReason::Admin,
        )
        .await
        .expect("every session ends");
    holder.commit().await.expect("commit");

    assert_eq!(decision.await.expect("decision"), StatusCode::FORBIDDEN);
    let consents = database.oidc().list_consents(flow.user_id).await;
    assert!(consents.expect("consents").is_empty(), "not saved");
}

/// PKCE is optional only for a confidential client, which authenticates at the
/// token endpoint (RFC 9700 §2.1.1): a public client's request without it is
/// refused, a challenge a confidential client sends is still enforced, and a
/// verifier for a code issued without a challenge is refused as a downgrade.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pkce_is_optional_only_for_confidential_clients() {
    /// The scenario's authorization request without PKCE, followed to its code.
    async fn without_pkce(flow: &Flow) -> Url {
        let mut url = flow.authorization_url(Scope::OpenId.as_str(), None, &[]);
        let kept: Vec<_> = url
            .query_pairs()
            .into_owned()
            .filter(|(name, _)| !name.starts_with("code_challenge"))
            .collect();
        url.query_pairs_mut().clear().extend_pairs(kept);
        let uri = format!("{}?{}", url.path(), url.query().expect("query"));
        flow.consent(flow.request(Method::GET, &uri, &[], None).await)
            .await
    }
    /// Exchanges `code` with the scenario's credentials and no verifier.
    async fn exchange_without_verifier(flow: &Flow, code: &str) -> Response {
        flow.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::AuthorizationCode.as_str()),
                ("redirect_uri", flow.client.redirect_uris[0].as_str()),
                ("code", code),
            ],
            flow.basic.as_deref(),
        )
        .await
    }

    let public = Flow::new(false, true).await;
    assert_eq!(
        parameter(&without_pkce(&public).await, "error"),
        OAuthCode::InvalidRequest.as_str()
    );

    let confidential = Flow::new(true, true).await;
    let downgraded = parameter(&without_pkce(&confidential).await, "code");
    let basic = confidential.basic.as_deref();
    Flow::assert_invalid_grant(
        confidential
            .exchange(&downgraded, Flow::verifier(), basic)
            .await,
    )
    .await;
    let code = parameter(&without_pkce(&confidential).await, "code");
    confidential
        .id_token(exchange_without_verifier(&confidential, &code).await)
        .await;
    let challenged = confidential.code(Scope::OpenId.as_str()).await;
    Flow::assert_invalid_grant(exchange_without_verifier(&confidential, &challenged).await).await;
}
