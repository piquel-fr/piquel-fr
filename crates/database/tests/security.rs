//! Persistence guarantees behind invitations and session passkey confirmations.
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, Handle, SessionId, TokenId, UserId,
    events::{Browser, Platform, UserAgentFamily},
};
use piquel_repository::{
    Database, DatabaseConfig, DatabaseError, InsertSession, InsertUser, SessionScope,
};
use std::net::IpAddr;
/// Invitations are single-use, and passkey confirmations belong to one session and end with it.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the invitation rollback and session lifecycle scenario together."
)]
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn invitation_redemption_and_confirmation_lifecycle() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let db = Database::connect(
        DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
    )
    .await
    .expect("connect");
    db.run_migrations().await.expect("migrate");
    let user = UserId::new();
    let digest = user.as_uuid().as_bytes().repeat(2);
    db.security()
        .create_invitation(TokenId::new(), &digest, Utc::now() + Duration::minutes(1))
        .await
        .expect("invite");
    let mut tx = db.begin().await.expect("transaction");
    assert!(
        tx.security()
            .redeem_invitation(&digest)
            .await
            .expect("redeem")
    );
    tx.rollback().await.expect("rollback");
    assert!(
        db.security()
            .invitation_active(&digest)
            .await
            .expect("rollback preserves invitation")
    );
    let redeem = || async {
        db.security()
            .redeem_invitation(&digest)
            .await
            .expect("redemption")
    };
    let (a, b) = tokio::join!(redeem(), redeem());
    assert_ne!(a, b, "exactly one concurrent redemption succeeds");
    db.users()
        .insert(&InsertUser {
            id: user,
            handle: Handle::parse(&format!("test-{}", &user.to_string()[24..])).expect("handle"),
            display_name: "Security test".into(),
        })
        .await
        .expect("user");
    let session = SessionId::new();
    let other = SessionId::new();
    let now = Utc::now();
    for id in [session, other] {
        db.sessions()
            .insert(&InsertSession {
                id,
                user_id: user,
                authentication_methods: vec![AuthenticationMethod::Federation],
                authenticated_at: now,
                expires_at: now + Duration::minutes(1),
                user_agent_family: UserAgentFamily {
                    browser: Browser::Firefox,
                    platform: Platform::Linux,
                },
                ip: IpAddr::from([192, 0, 2, 1]),
                passkey_confirmed_at: None,
            })
            .await
            .expect("session");
    }
    let database = &db;
    let confirmed_at = |id| async move {
        database
            .sessions()
            .find_active_by_id(id)
            .await
            .expect("lookup")
            .and_then(|session| session.passkey_confirmed_at)
    };
    assert!(
        confirmed_at(session).await.is_none(),
        "social sign-in has no confirmation"
    );
    let at = Utc::now() - Duration::seconds(30);
    for id in [session, other] {
        db.sessions()
            .confirm_passkey(id, at)
            .await
            .expect("confirm");
    }
    let stored = confirmed_at(session).await.expect("confirmation");
    assert!(
        (stored - at).abs() < Duration::milliseconds(1),
        "stored as given"
    );
    db.sessions()
        .revoke(user, SessionScope::AllExcept(session))
        .await
        .expect("revoke others");
    assert!(
        db.sessions()
            .find_by_id(other)
            .await
            .expect("other")
            .is_some_and(|other| other.revoked_at.is_some() && other.passkey_confirmed_at.is_none()),
        "revoking other sessions clears their confirmation"
    );
    assert!(confirmed_at(session).await.is_some(), "current preserved");
    db.sessions()
        .revoke(user, SessionScope::One(session))
        .await
        .expect("logout");
    assert!(
        matches!(
            db.sessions().confirm_passkey(session, Utc::now()).await,
            Err(DatabaseError::NotFound)
        ),
        "a revoked session cannot be confirmed"
    );
}
