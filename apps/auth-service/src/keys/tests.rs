//! Rotation, revocation and import on the shared test database. Each test works in
//! a transaction that holds the signing key lock and rolls back, so tests never
//! see each other's keys, and the replicas of other tests keep theirs.

use super::*;
use crate::{
    routes,
    service::ServiceApplication,
    tests::{Replicas, key_encryption_key},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use piquel_common::protocol::jwt::{Jwk, TokenType};
use piquel_repository::InsertSigningKey;
use serde_json::{Value, json};
use tower::ServiceExt;

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

/// Stores `key` in `state` as created `at`, with `public` as its public key, and
/// its private key sealed with `binding`, or `sealed` instead when given.
async fn insert(
    store: &KeyStore,
    tx: &mut DatabaseTransaction<'_>,
    key: &Rs256Key,
    state: SigningKeyState,
    (binding, sealed): (Binding, Option<Vec<u8>>),
    public: Jwk,
    at: DateTime<Utc>,
) -> KeyId {
    let id: KeyId = key.kid().parse().expect("key ID");
    let thumbprint = key.public_key().thumbprint().expect("thumbprint");
    let sealed_private_key = sealed.unwrap_or_else(|| {
        let associated = binding.associated_data(&id, SigningKeyType::Rsa, &thumbprint);
        let der = key.private_key_der().expect("DER");
        store.kek.seal(&der, &associated).expect("seal")
    });
    tx.signing_keys()
        .insert(&InsertSigningKey {
            id: id.clone(),
            key_type: SigningKeyType::Rsa,
            state,
            public_jwk: public,
            sealed_private_key,
            at,
        })
        .await
        .expect("insert");
    id
}

/// The IDs of the keys `keys` publishes.
fn kids(keys: &KeySet) -> Vec<String> {
    keys.jwks().keys.iter().map(|key| key.kid.clone()).collect()
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

/// Of two concurrent ticks, the one that takes the lock takes the step, and the
/// other skips the tick instead of waiting, so no step happens twice.
/// `rotation_takes_each_step_once_on_schedule` covers the steps themselves.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_ticks_take_each_step_once() {
    let (store, database) = store().await;
    let mut first = database.begin().await.expect("transaction");
    clear(&mut first).await;
    let mut second = database.begin().await.expect("transaction");
    let now = Utc::now();
    let (ran_first, ran_second) = tokio::join!(
        store.tick_in(&mut first, now),
        store.tick_in(&mut second, now)
    );
    assert!(ran_first.expect("first tick"));
    assert!(!ran_second.expect("second tick"), "the lock is held");
    let states = states(&mut first).await;
    assert!(
        matches!(states[..], [(_, SigningKeyState::Active)]),
        "{states:?}"
    );
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
    let mut change = Change::new(&mut tx, &store, Utc::now(), None);
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

    let mut change = Change::new(&mut tx, &store, Utc::now(), None);
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
    assert_eq!(kids(&keys), [replacement.to_string()]);
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
    let mut change = Change::new(&mut tx, &store, Utc::now(), None);
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

/// A `next` key whose private key does not open, or is not the private half of
/// its public key, is left out of the key set and refused at promotion, while
/// the active key keeps signing and the rest of rotation goes on; revoking it
/// lets rotation publish another. A key
/// sealed with its public key bound, as a later release will seal, opens, is
/// published and is promoted.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_next_key_that_cannot_sign_is_never_promoted() {
    let (store, database) = store().await;
    let mut tx = database.begin().await.expect("transaction");
    clear(&mut tx).await;
    let start = Utc::now();
    let due = start + PRE_PUBLICATION;
    assert!(store.tick_in(&mut tx, start).await.expect("first key"));
    let first: KeyId = key_set(&store, &mut tx)
        .await
        .signer()
        .kid()
        .parse()
        .expect("key ID");
    let mut change = Change::new(&mut tx, &store, start, None);
    let active = change.rotate(true).await.expect("rotate").to_string();
    let other = Rs256Key::generate("other").expect("another key");
    let unsealable = Rs256Key::generate("unsealable").expect("key");
    let mismatched = Rs256Key::generate("mismatched").expect("key");
    let cases = [
        (
            &unsealable,
            (Binding::Record, Some(vec![0; 64])),
            unsealable.public_key().jwk().clone(),
        ),
        (
            &mismatched,
            (Binding::Record, None),
            Jwk {
                kid: mismatched.kid().to_owned(),
                ..other.public_key().jwk().clone()
            },
        ),
    ];
    for (key, sealing, public) in cases {
        let next = insert(
            &store,
            &mut tx,
            key,
            SigningKeyState::Next,
            sealing,
            public,
            start,
        )
        .await;
        let keys = key_set(&store, &mut tx).await;
        assert_eq!(keys.signer().kid(), active);
        assert!(
            !kids(&keys).contains(&next.to_string()),
            "{next} is left out"
        );
        // The refusal leaves the rest of rotation going: the first key retires.
        let states = advance(&store, &mut tx, due).await;
        assert!(
            states.contains(&(next.clone(), SigningKeyState::Next)),
            "{states:?}"
        );
        assert!(
            states.contains(&(first.clone(), SigningKeyState::Retired)),
            "{states:?}"
        );
        let mut change = Change::new(&mut tx, &store, due, None);
        assert_eq!(change.revoke(&next).await.expect("revoke"), None);
    }

    let bound = Rs256Key::generate("bound").expect("key");
    let public = bound.public_key().jwk().clone();
    let next = insert(
        &store,
        &mut tx,
        &bound,
        SigningKeyState::Next,
        (Binding::PublicKey, None),
        public,
        start,
    )
    .await;
    let published = kids(&key_set(&store, &mut tx).await);
    assert!(published.contains(&next.to_string()), "{published:?}");
    assert!(store.tick_in(&mut tx, due).await.expect("promote"));
    assert_eq!(key_set(&store, &mut tx).await.signer().kid(), next.as_str());
    tx.rollback().await.expect("rollback");
}

/// No change goes ahead while the active key cannot be opened, except revoking
/// it, which replaces it with a key that signs.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoking_a_broken_active_key_recovers_the_key_set() {
    let (store, database) = store().await;
    let mut tx = database.begin().await.expect("transaction");
    clear(&mut tx).await;
    let key = Rs256Key::generate("broken").expect("key");
    let public = key.public_key().jwk().clone();
    let sealing = (Binding::Record, Some(vec![0; 64]));
    let broken = insert(
        &store,
        &mut tx,
        &key,
        SigningKeyState::Active,
        sealing,
        public,
        Utc::now(),
    )
    .await;
    assert!(matches!(
        store.check(&mut tx, None).await,
        Err(KeyError::Stored { .. })
    ));
    store
        .check(&mut tx, Some(&broken))
        .await
        .expect("revoking skips the check");
    let mut change = Change::new(&mut tx, &store, Utc::now(), None);
    let replacement = change
        .revoke(&broken)
        .await
        .expect("revoke")
        .expect("a replacement signs");
    assert_eq!(
        key_set(&store, &mut tx).await.signer().kid(),
        replacement.as_str()
    );
    tx.rollback().await.expect("rollback");
}

/// A replica whose reloads keep failing keeps its key set, but turns unready once
/// the set is five minutes old, and stops using it at fifteen. A reload that
/// succeeds makes it ready again.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_replica_that_cannot_reload_turns_unready() {
    let (store, database) = store().await;
    let keys = store.start().await.expect("keys");
    let ready = async || {
        let request = Request::get(routes::service::READY)
            .body(Body::empty())
            .expect("request");
        ServiceApplication::new(database.clone(), keys.clone())
            .routes()
            .oneshot(request)
            .await
            .expect("response")
            .status()
    };
    assert_eq!(ready().await, StatusCode::NO_CONTENT);
    // Its key-encryption key opens none of the stored keys.
    let failing = KeyStore::new(
        database.clone(),
        Arc::new(KeyEncryptionKey::generate().expect("another KEK")),
    );
    keys.age(UNREADY_AFTER + Duration::from_secs(1));
    failing.reload(&keys).await;
    assert_eq!(ready().await, StatusCode::SERVICE_UNAVAILABLE);
    assert!(keys.current().is_ok(), "an unready replica still signs");
    keys.age(STALE_AFTER + Duration::from_secs(1));
    failing.reload(&keys).await;
    assert!(keys.current().is_err(), "a stale key set is not used");
    store.reload(&keys).await;
    assert_eq!(ready().await, StatusCode::NO_CONTENT);
    assert!(keys.current().is_ok());
}
