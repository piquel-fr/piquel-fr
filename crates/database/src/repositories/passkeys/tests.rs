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

/// An account keeps at most 100 active passkeys, so the recovery event that lists
/// them stays within the audit chain's payload bound. A revoked one frees a place.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn accounts_keep_at_most_100_passkeys() {
    let pool = Database::test_pool().await;
    let account = InsertUser::named("passkeys");
    let user = account.id;
    UserRepository::from_pool(&pool)
        .insert(&account)
        .await
        .expect("user");
    sqlx::query(
        "INSERT INTO passkey_credentials (id, credential_id, user_id, credential, friendly_name)
        SELECT uuidv7(), uuid_send(uuidv7()), $1, '{}', 'Passkey test'
        FROM generate_series(1, 100)",
    )
    .bind(user.as_uuid())
    .execute(&pool)
    .await
    .expect("100 passkeys");
    let another = || InsertPasskey {
        id: PasskeyId::new(),
        credential_id: PasskeyId::new().as_uuid().as_bytes().to_vec(),
        user_id: user,
        credential: serde_json::json!({}),
        friendly_name: "Passkey test".into(),
    };
    let mut passkeys = PasskeyRepository::from_pool(&pool);
    assert!(
        passkeys.insert(&another()).await.is_err(),
        "a 101st passkey"
    );
    sqlx::query(
        "UPDATE passkey_credentials SET revoked_at = now()
        WHERE id = (SELECT id FROM passkey_credentials WHERE user_id = $1 LIMIT 1)",
    )
    .bind(user.as_uuid())
    .execute(&pool)
    .await
    .expect("revoke one");
    passkeys.insert(&another()).await.expect("a freed place");
}
