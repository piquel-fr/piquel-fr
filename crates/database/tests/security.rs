//! Persistence guarantees behind invitations and reusable management windows.
use chrono::{Duration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_repository::{Actor, Database, DatabaseConfig, InsertSession, InsertUser};
/// Invitations are single-use and management authorization follows session expiry and revocation.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the invitation rollback and session lifecycle scenario together."
)]
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn invitation_redemption_and_management_lifecycle() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let db = Database::connect(
        DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
    )
    .await
    .expect("connect");
    db.run_migrations().await.expect("migrate");
    let user = UserId::new();
    let digest = user.as_uuid().as_bytes().repeat(2);
    let operator = Actor::Cli {
        os_user: "test".into(),
        host: "test".into(),
    };
    let invite = |id, digest| {
        let operator = operator.clone();
        let db = &db;
        async move {
            db.security()
                .create_invitation(id, digest, Utc::now() + Duration::minutes(1), &operator)
                .await
                .expect("invite");
        }
    };
    invite(TokenId::new(), &digest).await;
    // A revoked invitation can no longer be redeemed, and is revoked only once.
    let revoked = TokenId::new();
    let revoked_digest = TokenId::new().as_uuid().as_bytes().repeat(2);
    invite(revoked, &revoked_digest).await;
    assert!(
        db.security()
            .revoke_invitation(revoked)
            .await
            .expect("revoke")
    );
    assert!(
        !db.security()
            .revoke_invitation(revoked)
            .await
            .expect("revoke again")
    );
    assert!(
        !db.security()
            .redeem_invitation(&revoked_digest)
            .await
            .expect("redeem revoked")
    );
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
            username: format!("test_{user}"),
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
                expires_at: now + Duration::seconds(3),
                user_agent_family: None,
            })
            .await
            .expect("session");
    }
    assert!(
        !db.sessions()
            .management_active(session)
            .await
            .expect("social has no grant")
    );
    let expiry = db
        .sessions()
        .grant_management(session)
        .await
        .expect("grant");
    assert!(
        expiry <= now + Duration::seconds(3),
        "management cannot outlive session"
    );
    for _ in 0..2 {
        assert!(
            db.sessions()
                .management_active(session)
                .await
                .expect("reusable grant")
        );
    }
    assert!(
        !db.sessions()
            .management_active(other)
            .await
            .expect("grant is session-bound")
    );
    db.sessions()
        .revoke_other(user, session)
        .await
        .expect("revoke others");
    assert!(
        db.sessions()
            .find_active_by_id(other)
            .await
            .expect("other")
            .is_none()
    );
    assert!(
        db.sessions()
            .management_active(session)
            .await
            .expect("current preserved")
    );
    db.sessions().revoke(session).await.expect("logout");
    assert!(
        !db.sessions()
            .management_active(session)
            .await
            .expect("logout invalidates grant")
    );
}
