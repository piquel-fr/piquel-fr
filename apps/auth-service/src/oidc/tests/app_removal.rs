//! Removing an app from an account ends its grants, codes and consent.

use super::*;

/// An administrator removes an account's app with the owner's own operation, which
/// `removing_an_app_ends_its_access` covers: the removal is recorded as the
/// administrator's, with the reason they gave.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_administrator_removes_an_app_with_a_reason() {
    let flow = Flow::new(false, false).await;
    flow.code(Scope::OpenId.as_str()).await;
    let harness = crate::admin::tests::Harness {
        database: flow.app.database.clone(),
    };
    let admin = harness.admin().await;
    let reason = "Reported as an impersonating app";
    let subject = crate::account::Subject::operator(
        flow.user_id,
        crate::admin::tests::operator(admin, Utc::now()),
        crate::Reason::parse(reason.into()).expect("reason"),
    );
    crate::account::AccountService::new(flow.app.database.clone())
        .remove_app(&subject, &flow.client.id)
        .await
        .expect("remove");
    let history = flow
        .app
        .database
        .events()
        .history_for_user(flow.user_id, 100)
        .await
        .expect("history");
    let removed = DomainEvent::ConsentRevoked {
        client_id: flow.client.id.clone(),
    };
    let stored = history
        .iter()
        .find(|stored| stored.event.known() == Some(&removed))
        .expect("recorded");
    let actor = Actor::Admin {
        user_id: admin.user_id,
        session_id: admin.session_id,
    };
    assert_eq!(stored.actor, actor);
    assert_eq!(stored.reason.as_deref(), Some(reason));
}

/// Removing an app from the account's settings ends its refresh grant and its
/// outstanding code, and forgets the consent, so it asks again. It is recorded
/// once, and listed no more.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn removing_an_app_ends_its_access() {
    let flow = Flow::new(false, false).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");
    let outstanding = flow.code(REFRESH_SCOPES).await;
    let service = crate::account::AccountService::new(flow.app.database.clone());
    let owner = flow.owner().await;
    let viewer = crate::account::Viewer::from(&owner);
    let apps = service.apps(&viewer).await.expect("apps");
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].client_id, flow.client.id);
    assert_eq!(apps[0].scopes, [Scope::OpenId.as_str()]);
    assert!(apps[0].offline && !apps[0].first_party);

    service
        .remove_app(&crate::account::Subject::from(owner), &flow.client.id)
        .await
        .expect("remove");
    assert!(service.apps(&viewer).await.expect("apps").is_empty());
    assert_eq!(
        flow.events().await[0],
        DomainEvent::ConsentRevoked {
            client_id: flow.client.id.clone()
        }
    );
    Flow::assert_invalid_grant(flow.refresh(refresh).await).await;
    Flow::assert_invalid_grant(flow.exchange(&outstanding, Flow::verifier(), None).await).await;
    let response = flow
        .authorize(REFRESH_SCOPES, Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
}

/// A code issued before the user withdrew consent is not exchanged after it,
/// even when it is not expired, as one an authorization issued just as a removal
/// withdrew the consent is not.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn withdrawn_consent_stops_an_issued_code() {
    let flow = Flow::new(false, false).await;
    let code = flow.code(Scope::OpenId.as_str()).await;
    flow.app
        .database
        .oidc()
        .revoke_consents(flow.user_id, Some(&flow.client.id))
        .await
        .expect("withdraw");
    Flow::assert_invalid_grant(flow.exchange(&code, Flow::verifier(), None).await).await;
}

/// An exchange that starts while an app's removal holds the account waits for it,
/// before taking its code, so even a first-party app, which needs no consent,
/// finds its code expired rather than creating a refresh grant after the removal.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_exchange_waits_for_a_removal_and_finds_its_code_expired() {
    let flow = Flow::new(false, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let database = flow.app.database.clone();
    let mut removal = database.begin().await.expect("transaction");
    removal
        .users()
        .find_active_by_id_for_update(flow.user_id)
        .await
        .expect("lock")
        .expect("user");
    let exchanging = flow.clone();
    let exchange = tokio::spawn(async move {
        let response = exchanging.exchange(&code, Flow::verifier(), None).await;
        (response.status(), Flow::json(response).await)
    });
    until_blocked(&mut removal, 1).await;
    removal
        .oidc()
        .expire_codes(flow.user_id, &flow.client.id)
        .await
        .expect("expire");
    removal.commit().await.expect("commit");

    let (status, body) = exchange.await.expect("exchange");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], OAuthCode::InvalidGrant.as_str());
}
