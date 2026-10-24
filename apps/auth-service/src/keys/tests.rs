//! Rotation, revocation and import on the shared test database. Each test works in
//! a transaction that holds the signing key lock and rolls back, so tests never
//! see each other's keys, and the replicas of other tests keep theirs.

use super::*;
use crate::tests::{Replicas, key_encryption_key};
use piquel_common::protocol::jwt::TokenType;
use serde_json::{Value, json};

/// The issuer the test tokens name.
const ISSUER: &str = "https://auth.example";

/// A store over the test database, sealing with the tests' key-encryption key.
async fn store() -> (KeyStore, Database) {
    let database = Replicas::database().await;
    (
        KeyStore::new(database.clone(), Arc::new(key_encryption_key())),
        database,
    )
}

/// Deletes every key in `tx`, after taking the lock.
async fn clear(tx: &mut DatabaseTransaction<'_>) {
    tx.signing_keys().lock().await.expect("lock");
    for key in tx.signing_keys().list().await.expect("list") {
        tx.signing_keys().delete(&key.id).await.expect("delete");
    }
}

/// The keys in `tx` and their states, oldest first.
async fn states(tx: &mut DatabaseTransaction<'_>) -> Vec<(KeyId, SigningKeyState)> {
    let keys = tx.signing_keys().list().await.expect("list");
    keys.into_iter().map(|key| (key.id, key.state)).collect()
}

/// The key set built from the keys in `tx`.
async fn key_set(store: &KeyStore, tx: &mut DatabaseTransaction<'_>) -> KeySet {
    store
        .key_set(&tx.signing_keys().list().await.expect("list"))
        .expect("key set")
}

/// An ID token signed by `keys`, already expired, as a logout hint may be.
fn hint(keys: &KeySet) -> String {
    let now = Utc::now().timestamp();
    keys.sign(
        TokenType::Id,
        &json!({"iss": ISSUER, "aud": "client", "iat": now - 600, "exp": now - 300}),
    )
    .expect("sign hint")
}

/// An unexpired access token signed by `keys`.
fn access_token(keys: &KeySet) -> String {
    let now = Utc::now().timestamp();
    keys.sign(
        TokenType::Access,
        &json!({"iss": ISSUER, "iat": now, "exp": now + 300}),
    )
    .expect("sign token")
}

/// Ticks twice at `at`, so a step taken twice would show, and returns the keys'
/// states, of which exactly one signs.
async fn advance(
    store: &KeyStore,
    tx: &mut DatabaseTransaction<'_>,
    at: DateTime<Utc>,
) -> Vec<(KeyId, SigningKeyState)> {
    for _ in 0..2 {
        assert!(
            store.tick_in(tx, at).await.expect("tick"),
            "the lock is held"
        );
    }
    let states = states(tx).await;
    let active = states
        .iter()
        .filter(|(_, state)| *state == SigningKeyState::Active)
        .count();
    assert_eq!(active, 1, "{states:?}");
    states
}

/// Each step happens once, when its time comes and not before: the first key
/// signs at once, a successor is published after 90 days and signs a day later,
/// the old key stays published while its tokens may be valid, then verifies only
/// hints for 30 days, and is then deleted. One key signs throughout.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rotation_takes_each_step_once_on_schedule() {
    let (store, database) = store().await;
    let mut tx = database.begin().await.expect("transaction");
    clear(&mut tx).await;
    let start = Utc::now();
    let states = advance(&store, &mut tx, start).await;
    let [(first, SigningKeyState::Active)] = &states[..] else {
        panic!("the first start generates an active key");
    };
    let first = first.clone();
    let first_set = key_set(&store, &mut tx).await;
    let (first_hint, first_token) = (hint(&first_set), access_token(&first_set));

    let published = start + ROTATION_PERIOD;
    assert_eq!(
        advance(&store, &mut tx, published - TimeDelta::seconds(1))
            .await
            .len(),
        1
    );
    let states = advance(&store, &mut tx, published).await;
    let [_, (second, SigningKeyState::Next)] = &states[..] else {
        panic!("a successor is published");
    };
    let second = second.clone();
    let keys = key_set(&store, &mut tx).await;
    assert_eq!(
        keys.signer().kid(),
        first.as_str(),
        "the next key does not sign yet"
    );
    assert_eq!(keys.jwks().keys.len(), 2);

    let activated = published + PRE_PUBLICATION;
    assert_eq!(
        advance(&store, &mut tx, activated - TimeDelta::seconds(1)).await,
        [
            (first.clone(), SigningKeyState::Active),
            (second.clone(), SigningKeyState::Next)
        ]
    );
    assert_eq!(
        advance(&store, &mut tx, activated).await,
        [
            (first.clone(), SigningKeyState::Retiring),
            (second.clone(), SigningKeyState::Active)
        ]
    );
    let keys = key_set(&store, &mut tx).await;
    assert_eq!(keys.signer().kid(), second.as_str());
    assert!(
        keys.verify::<Value>(&first_token, TokenType::Access, ISSUER)
            .is_ok(),
        "a retiring key's tokens verify"
    );
    assert!(keys.jwks().keys.iter().any(|key| key.kid == first.as_str()));

    let retired = activated + RETIRING_WINDOW;
    assert_eq!(
        advance(&store, &mut tx, retired - TimeDelta::seconds(1)).await[0].1,
        SigningKeyState::Retiring
    );
    assert_eq!(
        advance(&store, &mut tx, retired).await[0],
        (first.clone(), SigningKeyState::Retired)
    );
    let stored = tx.signing_keys().list().await.expect("list");
    assert!(
        stored[0].sealed_private_key.is_none(),
        "its private key is erased"
    );
    let keys = key_set(&store, &mut tx).await;
    assert!(keys.jwks().keys.iter().all(|key| key.kid != first.as_str()));
    assert!(matches!(
        keys.verify::<Value>(&first_token, TokenType::Access, ISSUER),
        Err(CryptoError::UnknownKey)
    ));
    assert!(
        keys.verify_id_token_hint(&first_hint, ISSUER).is_ok(),
        "a retired key's hints verify"
    );

    let deleted = retired + RETIRED_WINDOW;
    assert_eq!(
        advance(&store, &mut tx, deleted - TimeDelta::seconds(1))
            .await
            .len(),
        2
    );
    assert_eq!(
        advance(&store, &mut tx, deleted).await,
        [(second, SigningKeyState::Active)]
    );
    assert!(matches!(
        key_set(&store, &mut tx)
            .await
            .verify_id_token_hint(&first_hint, ISSUER),
        Err(CryptoError::UnknownKey)
    ));
    tx.rollback().await.expect("rollback");
}

/// At each step of the schedule, of two concurrent ticks, the one that takes the
/// lock takes the step, and the other skips the tick instead of waiting, so no
/// step happens twice.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_ticks_take_each_step_once() {
    use SigningKeyState::{Active, Next, Retired, Retiring};
    let (store, database) = store().await;
    let mut first = database.begin().await.expect("transaction");
    clear(&mut first).await;
    let mut second = database.begin().await.expect("transaction");
    let start = Utc::now();
    let published = start + ROTATION_PERIOD;
    let activated = published + PRE_PUBLICATION;
    let retired = activated + RETIRING_WINDOW;
    for (at, expected) in [
        (start, &[Active][..]),
        (published, &[Active, Next]),
        (activated, &[Retiring, Active]),
        (retired, &[Retired, Active]),
        (retired + RETIRED_WINDOW, &[Active]),
    ] {
        let (ran_first, ran_second) = tokio::join!(
            store.tick_in(&mut first, at),
            store.tick_in(&mut second, at)
        );
        assert!(ran_first.expect("first tick"));
        assert!(!ran_second.expect("second tick"), "the lock is held");
        let states: Vec<_> = states(&mut first)
            .await
            .into_iter()
            .map(|(_, state)| state)
            .collect();
        assert_eq!(states, expected, "at {at}");
    }
    second.rollback().await.expect("rollback");
    first.rollback().await.expect("rollback");
}

/// Revoking the active key removes it, the `next` key and the `retiring` key from
/// the key set at once, for tokens and hints alike, and a new key signs. Revoking
/// a key that does not sign needs no replacement, and an unknown key changes
/// nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoking_a_key_removes_it_and_replaces_the_signer() {
    let (store, database) = store().await;
    let mut tx = database.begin().await.expect("transaction");
    clear(&mut tx).await;
    let mut change = Change::new(&mut tx, &store.kek, Utc::now(), None);
    change.advance().await.expect("first key");
    change.rotate(true).await.expect("a second key signs");
    let next = change.rotate(false).await.expect("next key");
    let retiring = states(&mut tx)
        .await
        .into_iter()
        .find(|(_, state)| *state == SigningKeyState::Retiring)
        .expect("the first key retires")
        .0;
    let keys = key_set(&store, &mut tx).await;
    let revoked: KeyId = keys.signer().kid().parse().expect("key ID");
    let (token, revoked_hint) = (access_token(&keys), hint(&keys));

    let mut change = Change::new(&mut tx, &store.kek, Utc::now(), None);
    let replacement = change
        .revoke(&revoked)
        .await
        .expect("revoke")
        .expect("a replacement signs");
    assert!(matches!(
        change.revoke(&revoked).await,
        Err(KeyError::Unknown(_))
    ));
    assert!(
        matches!(change.revoke(&next).await, Err(KeyError::Unknown(_))),
        "the next key was revoked with the active one"
    );
    assert!(
        matches!(change.revoke(&retiring).await, Err(KeyError::Unknown(_))),
        "the retiring key was revoked with the active one"
    );
    let next = change.rotate(false).await.expect("another next key");
    assert_eq!(change.revoke(&next).await.expect("revoke next key"), None);
    let keys = key_set(&store, &mut tx).await;
    assert_eq!(keys.signer().kid(), replacement.as_str());
    assert!(matches!(
        keys.verify::<Value>(&token, TokenType::Access, ISSUER),
        Err(CryptoError::UnknownKey)
    ));
    assert!(matches!(
        keys.verify_id_token_hint(&revoked_hint, ISSUER),
        Err(CryptoError::UnknownKey)
    ));
    let kids: Vec<_> = keys.jwks().keys.iter().map(|key| key.kid.clone()).collect();
    assert_eq!(kids, [replacement.to_string()]);
    tx.rollback().await.expect("rollback");
}

/// The PEM key imports into an empty key set only, keeping its ID, and only the
/// key-encryption key that sealed it opens it again, or may change the keys.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn import_fills_an_empty_key_set_once() {
    let (store, database) = store().await;
    let mut tx = database.begin().await.expect("transaction");
    clear(&mut tx).await;
    let pem = Rs256Key::generate("primary").expect("PEM key");
    let token = access_token(&KeySet::single(
        Rs256Key::from_der("primary", &pem.private_key_der().expect("DER")).expect("copy"),
    ));
    let mut change = Change::new(&mut tx, &store.kek, Utc::now(), None);
    assert!(change.import(pem).await.expect("import"));
    let again = Rs256Key::generate("primary").expect("another PEM key");
    assert!(
        !change.import(again).await.expect("second import"),
        "keys exist"
    );
    let keys = key_set(&store, &mut tx).await;
    assert_eq!(keys.signer().kid(), "primary");
    assert!(
        keys.verify::<Value>(&token, TokenType::Access, ISSUER)
            .is_ok(),
        "tokens the PEM key signed keep verifying"
    );

    let other = KeyStore::new(
        database.clone(),
        Arc::new(KeyEncryptionKey::generate().expect("another KEK")),
    );
    assert!(matches!(
        other.key_set(&tx.signing_keys().list().await.expect("list")),
        Err(KeyError::Stored {
            source: CryptoError::Unsealable,
            ..
        })
    ));
    assert!(
        matches!(
            other.tick_in(&mut tx, Utc::now() + ROTATION_PERIOD).await,
            Err(KeyError::Stored { .. })
        ),
        "a store whose key-encryption key does not open the keys changes nothing"
    );
    tx.rollback().await.expect("rollback");
}
