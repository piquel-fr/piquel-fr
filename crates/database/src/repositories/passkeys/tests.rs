use super::{InsertPasskey, PasskeyRepository};
use crate::{Database, InsertUser, repositories::UserRepository};
use piquel_common::PasskeyId;

/// A disabled account and an account whose only passkey is revoked list no
/// credentials, like a handle nobody holds.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn handle_lookup_hides_disabled_accounts_and_revoked_passkeys() {
    let pool = Database::test_pool().await;
    let mut passkeys = PasskeyRepository::from_pool(&pool);
    for disable in [true, false] {
        let account = InsertUser::named("passkey");
        let user = account.id;
        UserRepository::from_pool(&pool)
            .insert(&account)
            .await
            .expect("user");
        let key = passkeys
            .insert(&InsertPasskey {
                id: PasskeyId::new(),
                credential_id: user.as_uuid().as_bytes().to_vec(),
                user_id: user,
                credential: serde_json::json!({}),
                friendly_name: "Passkey test".into(),
            })
            .await
            .expect("passkey");
        let listed = || async {
            PasskeyRepository::from_pool(&pool)
                .list_active_by_handle(&account.handle)
                .await
                .expect("lookup")
                .len()
        };
        assert_eq!(listed().await, 1);
        if disable {
            sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
                .bind(user.as_uuid())
                .execute(&pool)
                .await
                .expect("disable");
        } else {
            assert!(passkeys.revoke(key.id, user).await.expect("revoke"));
        }
        assert_eq!(listed().await, 0, "disable: {disable}");
    }
}
