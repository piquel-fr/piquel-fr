//! The lock serializes key changes, and the table keeps one active key per type.

use super::*;
use crate::Database;
use piquel_common::protocol::jwt::KeyType;

/// A key `id` in `state`, with placeholder key material the table does not check.
fn key(id: &str, state: SigningKeyState) -> InsertSigningKey {
    InsertSigningKey {
        id: id.parse().expect("key ID"),
        key_type: SigningKeyType::Rsa,
        state,
        public_jwk: Jwk {
            alg: None,
            e: "AQAB".into(),
            kid: id.into(),
            kty: KeyType::Rsa,
            n: "AQAB".into(),
            key_use: None,
        },
        sealed_private_key: vec![0; 32],
        at: Utc::now(),
    }
}

/// While one transaction holds the lock, another cannot take it. Every change is
/// rolled back, so other tests never see these keys.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn the_lock_excludes_and_one_key_per_type_signs() {
    let database = Database {
        pool: Database::test_pool().await,
    };
    let mut holder = database.begin().await.expect("transaction");
    holder.signing_keys().lock().await.expect("lock");
    let mut other = database.begin().await.expect("transaction");
    assert!(!other.signing_keys().try_lock().await.expect("try lock"));
    other.rollback().await.expect("rollback");
    assert!(
        database.signing_keys().lock().await.is_err(),
        "the pool has no transaction"
    );

    let mut keys = holder.signing_keys();
    for existing in keys.list().await.expect("list") {
        keys.delete(&existing.id).await.expect("delete");
    }
    let suffix = piquel_common::UserId::new();
    let first = key(&format!("first-{suffix}"), SigningKeyState::Active);
    keys.insert(&first).await.expect("first active key");
    keys.insert(&key(&format!("next-{suffix}"), SigningKeyState::Next))
        .await
        .expect("next key");
    assert!(matches!(
        keys.activate(&first.id, Utc::now()).await,
        Err(DatabaseError::NotFound)
    ));
    assert!(matches!(
        keys.insert(&key(&format!("second-{suffix}"), SigningKeyState::Active))
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    holder.rollback().await.expect("rollback");
}
