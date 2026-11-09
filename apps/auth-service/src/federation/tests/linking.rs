//! Linking pending provider evidence to a confirmed account, and unlinking it.

use super::*;
use crate::account::{AccountError, AccountService};

impl TestApp {
    /// Links this browser's pending evidence, its `pending` headers, to the account
    /// of the session `cookie` names, as the sign-in page does.
    async fn link_pending(
        &self,
        cookie: &str,
        pending: &HeaderMap,
    ) -> Result<String, AccountError> {
        let account = AccountService::new(self.app.database.clone());
        let owner = account
            .owner(security::RequestContext::TEST, &Self::cookies(cookie))
            .await
            .expect("session lookup")
            .expect("signed in");
        account
            .link_identity(&owner, &self.email, pending)
            .await
            .map(|(return_to, _)| return_to)
    }
}

/// Linking and unlinking require the intended account’s recent passkey confirmation;
/// unlink frees the subject and preserves email.
#[expect(
    clippy::too_many_lines,
    reason = "Keep one pending link from rejection through linking and unlinking together."
)]
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn linking_requires_target_confirmation_and_unlink_releases_subject_without_changing_email() {
    let test = TestApp::new().await;
    let email = format!("{}@example.com", TokenId::new());
    let target = test.user(Some(&email), true).await;
    let other = test.user(None, true).await;
    let observed = format!("{}@example.com", TokenId::new());
    let (pending, pending_headers) = test.pending(Some(target), Some(&observed)).await;
    let (_, other_cookie) = test.session(other, true).await;
    let (target_session, target_cookie) = test.session(target, false).await;
    let (other_session, _) = test.session(target, false).await;
    let refused = test.link_pending(&other_cookie, &pending_headers).await;
    assert!(
        matches!(
            refused,
            Err(AccountError::Identity(FederationError::LinkAccountMismatch))
        ),
        "another account's confirmation cannot link: {refused:?}"
    );
    // Confirmation comes first, before the browser's pending cookie is read.
    for pending in [&pending_headers, &HeaderMap::new()] {
        let refused = test.link_pending(&target_cookie, pending).await;
        assert!(
            matches!(
                refused,
                Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
            ),
            "an unconfirmed session cannot link: {refused:?}"
        );
    }
    let router = test.routes();
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::DELETE,
            "/account/social-identities/github",
            Some(&target_cookie),
            &serde_json::json!({}),
        ))
        .await
        .expect("unconfirmed rejection");
    security::tests::assert_step_up_required(response).await;
    test.app
        .database
        .sessions()
        .confirm_passkey(target_session, PasskeyId::new(), chrono::Utc::now())
        .await
        .expect("confirm");
    let return_to = test
        .link_pending(&target_cookie, &pending_headers)
        .await
        .expect("link");
    assert_eq!(return_to, pending.return_to);
    assert!(
        test.app
            .database
            .sessions()
            .find_active_by_id(other_session)
            .await
            .expect("other session")
            .is_some()
    );
    assert_eq!(
        test.app
            .database
            .emails()
            .find_active_verified(&email)
            .await
            .expect("email")
            .expect("owner")
            .user_id,
        target
    );
    assert!(
        test.app
            .database
            .emails()
            .find_active_verified(&observed)
            .await
            .expect("observation")
            .is_none()
    );
    let response = router
        .oneshot(TestApp::request(
            Method::DELETE,
            "/account/social-identities/github",
            Some(&target_cookie),
            &serde_json::json!({}),
        ))
        .await
        .expect("unlink");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        test.app
            .database
            .sessions()
            .find_active_by_id(other_session)
            .await
            .expect("revoked other session")
            .is_none()
    );
    test.app
        .database
        .federation()
        .insert_identity(&FederationApplication::identity(&pending, other))
        .await
        .expect("unlinked subject reusable");
}
