//! Each authorization step checks its client's registration as it is now.

use super::*;
use crate::{
    ClientRegistry,
    tests::{operator, reason, replace},
};
use sourceorigin_common::clients::RedirectUris;

/// Suspending an app while one of its codes is exchanged issues nothing: the
/// exchange checks the app under its share lock, so it waits for the suspension
/// to commit, then sees it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn suspending_an_app_during_an_exchange_issues_nothing() {
    let flow = Flow::new(false, false).await;
    let code = flow.code(Scope::OpenId.as_str()).await;
    let database = flow.app.database.clone();
    let mut suspension = database.begin().await.expect("transaction");
    ClientRegistry::new(&mut suspension, operator().context(&reason()))
        .set_suspended(&flow.client.id, true)
        .await
        .expect("suspended");
    let exchanging = flow.clone();
    let exchange =
        tokio::spawn(async move { exchanging.exchange(&code, Flow::verifier(), None).await });
    until_blocked(&mut suspension, 1).await;
    suspension.commit().await.expect("commit");

    let response = exchange.await.expect("exchange");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidGrant.as_str()
    );
    let events = flow.events().await;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, DomainEvent::GrantIssued { .. })),
        "{events:?}"
    );
}

/// A pending request follows its app's registration as it changes: once its
/// redirect URI is removed, or the app must push its requests, neither resuming
/// nor approving it leads the browser on to the app, and no code is issued.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pending_requests_follow_their_apps_registration() {
    let moved = RedirectUris::new(["https://moved.example/callback".parse().expect("URI")])
        .expect("one callback");
    for push in [false, true] {
        let name = if push {
            "pushing required"
        } else {
            "redirect removed"
        };
        let flow = Flow::new(false, false).await;
        let pending = location(&flow.authorize(Scope::OpenId.as_str(), None).await);
        assert_eq!(pending.path(), routes::page::CONSENT, "{name}");
        let transaction = parameter(&pending, "transaction");
        let client = if push {
            ClientRegistration {
                require_pushed_authorization_requests: true,
                ..flow.client.clone()
            }
        } else {
            ClientRegistration {
                redirect_uris: moved.clone(),
                ..flow.client.clone()
            }
        };
        replace(&flow.app.database, &client).await.expect(name);

        let resume = format!("/oauth/authorize/resume?transaction={transaction}");
        let resumed = flow.request(Method::GET, &resume, &[], None).await;
        let approve = [
            ("transaction", transaction.as_str()),
            ("decision", "approve"),
        ];
        let approved = flow
            .request(Method::POST, routes::page::CONSENT, &approve, None)
            .await;
        for response in [resumed, approved] {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            assert!(response.headers().get(header::LOCATION).is_none(), "{name}");
        }
        let events = flow.events().await;
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, DomainEvent::ConsentGranted { .. })),
            "{name}: {events:?}"
        );
    }
}

/// Approving consent locks the account before the app, as an owner changing their
/// app does, so an approval and a change to the app made at once never deadlock:
/// the approval waits for the change, then goes on.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn consent_waits_for_an_owners_change_to_the_app() {
    let flow = Flow::new(false, false).await;
    let pending = location(&flow.authorize(Scope::OpenId.as_str(), None).await);
    let transaction = parameter(&pending, "transaction");
    let database = flow.app.database.clone();
    let mut change = database.begin().await.expect("transaction");
    change
        .users()
        .find_active_by_id_for_update(flow.user_id)
        .await
        .expect("lock")
        .expect("account");
    let approving = flow.clone();
    let approval = tokio::spawn(async move {
        let form = [
            ("transaction", transaction.as_str()),
            ("decision", "approve"),
        ];
        approving
            .request(Method::POST, routes::page::CONSENT, &form, None)
            .await
            .status()
    });
    until_blocked(&mut change, 1).await;
    change
        .oidc()
        .lock_client(&flow.client.id)
        .await
        .expect("the app is free to change");
    change.commit().await.expect("commit");
    assert_eq!(approval.await.expect("approval"), StatusCode::SEE_OTHER);
}
