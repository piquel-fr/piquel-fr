//! Session lookup, passkey confirmation age and session locking against logout.

use super::*;
use piquel_common::{Handle, TokenId};
use piquel_crypto::Secret;
use piquel_repository::{InsertSession, InsertUser};

/// A session lookup failure stays a server error rather than becoming an anonymous session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn optional_session_preserves_database_failure_instead_of_reporting_signed_out() {
    // The timeout also bounds the first connection, so it leaves room for
    // connecting while other database tests run.
    let database = SecurityFixture::database(1, std::time::Duration::from_secs(1)).await;
    // Exhaust only this test's private pool; the database and all other tests
    // remain usable. A well-formed session cookie must trigger a real lookup.
    let transaction = database.begin().await.expect("hold sole connection");
    assert!(
        Session::optional(&database, &HeaderMap::new())
            .await
            .expect("no cookie requires no lookup")
            .is_none()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-piquel_session={}",
            Secret::generate().expect("browser secret").encoded()
        ))
        .expect("cookie"),
    );
    let error = Session::optional(&database, &headers)
        .await
        .expect_err("database timeout must propagate");
    assert_eq!(
        ApiError::from(error).into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    transaction.rollback().await.expect("release connection");
}

/// A confirmation counts from its own timestamp, against each action's maximum age.
#[test]
fn confirmation_age_is_fixed_from_its_timestamp() {
    let session = |age: Option<i64>| {
        let now = Utc::now();
        StoredSession {
            id: SessionId::new(),
            user_id: UserId::new(),
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now - Duration::days(1),
            expires_at: now + Duration::days(1),
            last_seen_at: now,
            revoked_at: None,
            passkey_confirmed_at: age.map(|age| now - Duration::seconds(age)),
            user_agent_family: None,
            last_seen_ip: None,
        }
    };
    assert!(Confirmed::<CONFIRMATION_MAX_AGE>::check(&session(Some(290))).is_ok());
    for age in [None, Some(310), Some(86_400)] {
        assert!(matches!(
            Confirmed::<CONFIRMATION_MAX_AGE>::check(&session(age)),
            Err(SessionError::StepUpRequired {
                max_age: CONFIRMATION_MAX_AGE
            })
        ));
    }
    assert!(matches!(
        Confirmed::<60>::check(&session(Some(90))),
        Err(SessionError::StepUpRequired { max_age: 60 })
    ));
}

/// A confirmed change holds the session row, so a racing logout waits for it, and a
/// change after logout fails.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmed_changes_serialize_with_logout() {
    let database = SecurityFixture::database(5, std::time::Duration::from_secs(5)).await;
    database.run_migrations().await.expect("migrations");
    let user_id = UserId::new();
    let mut tx = database.begin().await.expect("transaction");
    tx.users()
        .insert(&InsertUser {
            id: user_id,
            handle: Handle::parse(&format!("lock-{}", &TokenId::new().to_string()[24..]))
                .expect("handle"),
            display_name: "Lock test".into(),
        })
        .await
        .expect("user");
    let secret = Session::create(
        &mut tx,
        RequestContext::TEST,
        user_id,
        AuthenticationMethod::Passkey.into(),
    )
    .await
    .expect("session");
    tx.commit().await.expect("commit");
    let session = database
        .sessions()
        .find_active_by_browser_secret(secret.digest().as_bytes())
        .await
        .expect("lookup")
        .expect("session");
    let id = session.id;
    let mut change = database.begin().await.expect("change transaction");
    let locked = Session::lock(&mut change, &session).await.expect("lock");
    <Confirmed>::check(&locked).expect("passkey sign-in confirms");
    let logout = tokio::spawn({
        let database = database.clone();
        async move {
            let context = RequestContext::TEST.actor(Actor::User {
                user_id,
                session_id: Some(id),
            });
            let mut logout = database.begin().await?;
            let revoked = logout
                .revoke_sessions(
                    &context,
                    user_id,
                    SessionScope::One(id),
                    &RevocationReason::Logout,
                )
                .await?;
            logout.commit().await.map(|()| revoked)
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!logout.is_finished(), "logout must wait for the change");
    change.commit().await.expect("commit change");
    assert_eq!(logout.await.expect("logout task").expect("logout"), [id]);
    let mut change = database.begin().await.expect("change transaction");
    assert!(matches!(
        Session::lock(&mut change, &session).await,
        Err(SessionError::Missing)
    ));
}

/// A session that expires while a change waits for the account lock is rejected once
/// the lock is acquired, even though the lookup compares with the transaction's start.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn session_lock_rechecks_expiry_after_waiting() {
    let database = SecurityFixture::database(5, std::time::Duration::from_secs(5)).await;
    database.run_migrations().await.expect("migrations");
    let user_id = UserId::new();
    let now = Utc::now();
    let mut tx = database.begin().await.expect("transaction");
    tx.users()
        .insert(&InsertUser {
            id: user_id,
            handle: Handle::parse(&format!("lock-{}", &TokenId::new().to_string()[24..]))
                .expect("handle"),
            display_name: "Lock test".into(),
        })
        .await
        .expect("user");
    let session = tx
        .sessions()
        .insert(&InsertSession {
            id: SessionId::new(),
            user_id,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now,
            expires_at: now + Duration::seconds(1),
            user_agent_family: RequestContext::TEST.user_agent_family,
            ip: RequestContext::TEST.client_ip,
            passkey_confirmed_at: Some(now),
            passkey_id: None,
        })
        .await
        .expect("session");
    tx.commit().await.expect("commit");
    let mut holder = database.begin().await.expect("holder transaction");
    holder
        .users()
        .find_active_by_id_for_update(user_id)
        .await
        .expect("account lock")
        .expect("active account");
    let change = tokio::spawn({
        let database = database.clone();
        async move {
            let mut change = database.begin().await.expect("change transaction");
            Session::lock(&mut change, &session).await.map(drop)
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    holder.rollback().await.expect("release account");
    assert!(matches!(
        change.await.expect("change task"),
        Err(SessionError::Missing)
    ));
}
