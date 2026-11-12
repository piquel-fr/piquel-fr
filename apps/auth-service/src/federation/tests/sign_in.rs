//! Social sign-in: subject precedence over email, the passkey requirement, and
//! re-authenticating the browser's existing session.

use super::*;
use sourceorigin_repository::InsertExternalIdentity;

impl TestApp {
    /// Links this fixture's provider subject to `user_id`.
    async fn link(&self, user_id: UserId) {
        self.app
            .database
            .federation()
            .insert_identity(&InsertExternalIdentity {
                id: TokenId::new(),
                user_id,
                provider: sourceorigin_common::Provider::GitHub,
                issuer: ProviderEndpoints::new(Provider::GitHub)
                    .expect("GitHub facts")
                    .issuer
                    .into(),
                subject: self.subject.clone(),
                linked_email: None,
            })
            .await
            .expect("known identity");
    }
    /// Finds the active session a cookie pair names.
    async fn active(&self, cookie: &str) -> Option<StoredSession> {
        security::Session::optional(&self.app.database, &Self::cookies(cookie))
            .await
            .expect("session lookup")
    }
    /// The session cookie pair `response` sets.
    fn session_cookie(response: &Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie"))
            .find(|cookie| cookie.starts_with(BrowserCookie::Session.as_str()))
            .expect("session cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned()
    }
}

/// Stable provider subjects take priority over email observations and require an existing passkey.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn callback_email_collision_never_links_and_known_subject_never_bootstraps_a_missing_key() {
    let observed = format!("{}@example.com", TokenId::new());
    let original = format!("{}@example.com", TokenId::new());
    let test = TestApp::with_email(Some(&observed)).await;
    let email_owner = test.user(Some(&observed), true).await;
    let response = test.callback().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login?social=link");
    assert!(
        test.app
            .database
            .federation()
            .find_active(
                ProviderEndpoints::new(Provider::GitHub)
                    .expect("GitHub facts")
                    .issuer,
                &test.subject
            )
            .await
            .expect("identity")
            .is_none()
    );
    let subject_owner = test.user(Some(&original), false).await;
    test.link(subject_owner).await;
    // Known accounts cannot bootstrap from social login.
    let response = test.callback().await;
    TestApp::refused(&response, "account_unavailable");
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, subject_owner).await;
    tx.commit().await.expect("commit");
    let response = test.callback().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], DEFAULT_RETURN_TO);
    let session = test
        .active(&TestApp::session_cookie(&response))
        .await
        .expect("social session");
    assert_eq!(
        session.user_id, subject_owner,
        "stable subject takes priority over email observation"
    );
    assert!(
        session.passkey_confirmed_at.is_none(),
        "social sign-in never confirms a passkey"
    );
    // Signing in moves neither account's verified address.
    for (address, owner) in [(&observed, email_owner), (&original, subject_owner)] {
        assert_eq!(
            test.app
                .database
                .emails()
                .find_active_verified(address)
                .await
                .expect("email lookup")
                .expect("owner")
                .user_id,
            owner
        );
    }
}

/// Social sign-in re-authenticates the browser's own unconfirmed session in place,
/// refuses to re-authenticate one a passkey confirmed, and replaces another
/// account's session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn social_sign_in_reauthenticates_only_unconfirmed_sessions() {
    let test = TestApp::new().await;
    let owner = test.user(None, true).await;
    test.link(owner).await;

    let (social, cookie) = test.session(owner, false).await;
    let before = test.active(&cookie).await.expect("social session");
    let response = test.callback_from(Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let renewed = test
        .active(&TestApp::session_cookie(&response))
        .await
        .expect("renewed session");
    assert_eq!(renewed.id, social, "the session ID is kept");
    assert!(renewed.authenticated_at > before.authenticated_at);
    assert!(test.active(&cookie).await.is_none(), "old cookie ends");

    let (confirmed, cookie) = test.session(owner, true).await;
    let response = test.callback_from(Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .expect("location")
            .contains("error=passkey_required")
    );
    assert_eq!(
        test.active(&cookie).await.expect("untouched session").id,
        confirmed
    );

    let other = test.user(None, true).await;
    let (replaced, cookie) = test.session(other, false).await;
    let response = test.callback_from(Some(&cookie)).await;
    let session = test
        .active(&TestApp::session_cookie(&response))
        .await
        .expect("new session");
    assert_eq!(session.user_id, owner);
    assert_ne!(session.id, replaced);
    assert!(
        test.app
            .database
            .sessions()
            .find_by_id(replaced)
            .await
            .expect("lookup")
            .expect("session")
            .revoked_at
            .is_some(),
        "the other account's session is revoked"
    );
}
