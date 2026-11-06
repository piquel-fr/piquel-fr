//! Signup from pending provider evidence, committed only with a first passkey.

use super::*;
use piquel_common::events::{Actor, DomainEvent};

impl TestApp {
    /// Attaches the pending signup `pending` names, found by the browser's `headers`,
    /// to `user`'s new account, as a signup from `ip` does.
    async fn attach(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        ip: std::net::IpAddr,
        pending: TokenId,
        headers: &HeaderMap,
        user: UserId,
    ) -> Result<Option<ProviderPicture>, FederationError> {
        let actor = security::RequestContext::TEST.actor(Actor::Anonymous);
        FederationApplication::attach_signup(tx, &actor, &self.email, ip, pending, headers, user)
            .await
    }
}

/// Signup must create its first passkey and cannot claim an existing account’s email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn onboarding_commits_only_with_first_key_and_browser_and_never_claims_existing_email() {
    let test = TestApp::new().await;
    let (pending, headers) = test.pending(None, None).await;
    assert!(
        FederationApplication::pending_signup(&test.app.database, &headers, TokenId::new())
            .await
            .is_err(),
        "registration must name the displayed pending signup"
    );
    FederationApplication::pending_signup(&test.app.database, &headers, pending.id)
        .await
        .expect("pending signup");
    let user = test.user(None, false).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        test.attach(
            &mut tx,
            security::RequestContext::TEST.client_ip,
            pending.id,
            &headers,
            user
        )
        .await
        .is_err()
    );
    tx.rollback().await.expect("rollback");
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, user).await;
    assert!(
        test.attach(
            &mut tx,
            security::RequestContext::TEST.client_ip,
            pending.id,
            &HeaderMap::new(),
            user
        )
        .await
        .is_err()
    );
    test.attach(
        &mut tx,
        security::RequestContext::TEST.client_ip,
        pending.id,
        &headers,
        user,
    )
    .await
    .expect("first key authorizes signup");
    tx.commit().await.expect("commit");
    assert_eq!(
        test.app
            .database
            .federation()
            .find_active(&pending.issuer, &pending.subject)
            .await
            .expect("identity")
            .expect("linked")
            .user_id,
        user
    );
    let email = format!("{}@example.com", TokenId::new());
    test.user(Some(&email), true).await;
    let (pending, headers) = test.pending(None, Some(&email)).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        test.attach(
            &mut tx,
            security::RequestContext::TEST.client_ip,
            pending.id,
            &headers,
            user
        )
        .await
        .is_err()
    );
    tx.rollback().await.expect("rollback");
}

/// A signup's provider address joins the account recorded as imported from it:
/// verified and primary when the provider hosts it, otherwise unverified with its
/// verification link, since it may have changed owners since the provider
/// verified it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signup_imports_the_provider_address_verified_only_where_the_provider_is_authoritative() {
    let test = TestApp::new().await;
    for authoritative in [true, false] {
        let address = format!("{}@example.com", TokenId::new());
        let (pending, headers) = test
            .pending_from(|pending| PendingFederation {
                provider: Provider::Google,
                email: Some(address.clone()),
                email_authoritative: authoritative,
                ..pending
            })
            .await;
        let user = test.user(None, true).await;
        // A client IP of its own, so no other test shares its verification limit.
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(user.as_uuid().as_u128()));
        let mut tx = test.app.database.begin().await.expect("tx");
        test.attach(&mut tx, ip, pending.id, &headers, user)
            .await
            .expect("signup");
        tx.commit().await.expect("commit");

        let emails = test.app.database.emails().list(user).await.expect("emails");
        let [email] = emails.as_slice() else {
            panic!("one imported address: {emails:?}");
        };
        assert_eq!(email.normalized_email, address);
        assert_eq!(email.verified_at.is_some(), authoritative);
        assert_eq!(email.is_primary, authoritative);
        let history: Vec<_> = test
            .app
            .database
            .events()
            .history_for_user(user, 10)
            .await
            .expect("history")
            .into_iter()
            .map(|stored| stored.event.known().cloned().expect("known"))
            .collect();
        assert!(
            history.iter().any(|event| matches!(
                event,
                DomainEvent::EmailAdded { email_id, provider: Some(Provider::Google), .. }
                    if *email_id == email.id
            )),
            "{history:?}"
        );
        let kinds: Vec<_> = history.iter().map(DomainEvent::kind).collect();
        let expected: &[&str] = if authoritative {
            &[
                "primary_email_changed",
                "email_verified",
                "email_added",
                "identity_linked",
            ]
        } else {
            &["email_added", "identity_linked"]
        };
        assert_eq!(&kinds[..expected.len()], expected);
        let destination = format!("account {user}, address {}", email.id);
        let queued = test
            .app
            .database
            .deliveries()
            .payloads(&destination)
            .await
            .expect("deliveries");
        let expected: &[serde_json::Value] = if authoritative {
            &[]
        } else {
            &[serde_json::json!({"type": "verify_address", "email_id": email.id})]
        };
        assert_eq!(
            queued, expected,
            "only an unverified address is sent a link"
        );
    }
}

/// An address an account scheduled for deletion still holds is not imported, and
/// the signup goes on without it: restoring that account finds it again.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signup_skips_an_address_an_account_being_deleted_holds() {
    let test = TestApp::new().await;
    let address = format!("{}@gmail.com", TokenId::new());
    let deleting = test.user(Some(&address), true).await;
    test.app
        .database
        .users()
        .set_status(deleting, piquel_common::AccountStatus::Deleting)
        .await
        .expect("deleting");
    let (pending, headers) = test
        .pending_from(|pending| PendingFederation {
            provider: Provider::Google,
            email: Some(address.clone()),
            email_authoritative: true,
            ..pending
        })
        .await;
    let user = test.user(None, true).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    test.attach(
        &mut tx,
        security::RequestContext::TEST.client_ip,
        pending.id,
        &headers,
        user,
    )
    .await
    .expect("signup goes on");
    tx.commit().await.expect("commit");
    let emails = test.app.database.emails().list(user).await.expect("emails");
    assert!(emails.is_empty(), "{emails:?}");
}
