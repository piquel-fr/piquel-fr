//! Deleting a client: the tombstone it leaves, and the token grants it revokes
//! without deadlocking.
use super::*;
use crate::tests::{refresh_grant, sign_out};
use piquel_common::{TokenId, events::Actor};
use piquel_repository::RefreshRotationError;
use tokio::task::JoinHandle;

/// A public client and an account holding refresh grants to it, which the
/// deletion scenarios race a deletion against.
struct Granting {
    /// The scenario database.
    database: Database,
    /// The client, which an operator manages.
    client: ClientId,
    /// The account, signed in.
    user: Browser,
}

impl Granting {
    /// Registers the client over a migrated test database, and signs the account
    /// in.
    async fn new() -> Self {
        let database = Replicas::database().await;
        let client = registration(ClientKind::Public, "https://notes.example");
        register(&database, &client).await.expect("client");
        Self {
            user: Browser::new_account(&database).await,
            client: client.id,
            database,
        }
    }

    /// Issues the refresh grant `family` to the client from the account's session,
    /// and returns its first refresh token's ID and digest.
    async fn grant(&self, family: TokenId) -> (TokenId, Vec<u8>) {
        let user = &self.user;
        refresh_grant(
            &self.database,
            user.user_id,
            user.session_id,
            &self.client,
            family,
        )
        .await
    }

    /// Deletes the client as an operator, in a task of its own.
    fn delete(&self) -> JoinHandle<Result<(), ClientRegistryError>> {
        let (database, id) = (self.database.clone(), self.client.clone());
        tokio::spawn(
            async move { change(&database, async |registry| registry.delete(&id).await).await },
        )
    }
}

/// Deleting a client revokes its refresh tokens, removes its secrets and leaves a
/// disabled tombstone, recorded as the owner's. Its ID can never be registered,
/// applied, enabled, changed or deleted again, by the account or an operator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deleted_clients_stay_deleted() {
    let account = Account::new().await;
    let (database, alice) = (&account.database, &account.browser);
    let owner = account.owner().await;
    let client_id = account.create(ClientKind::Confidential).await;
    let (token, digest) = refresh_grant(
        database,
        alice.user_id,
        alice.session_id,
        &client_id,
        TokenId::new(),
    )
    .await;

    let client = account.find(owner.clone(), &client_id).await;
    account
        .service
        .delete_client(&client)
        .await
        .expect("delete");
    let found = account
        .service
        .owned_client(owner.clone(), client_id.as_str());
    assert!(matches!(
        found.await,
        Err(AccountError::Client(OwnedClientError::NotFound))
    ));
    assert_eq!(account.service.clients(&owner).await.expect("list"), []);

    let mut tx = database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), client_id.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
    drop(tx);
    let oidc = &mut database.oidc();
    let tombstone = oidc.find_client(client_id.as_str()).await;
    let tombstone = tombstone.expect("lookup").expect("row");
    assert!(tombstone.deleted_at.is_some() && !tombstone.enabled);
    assert_eq!(oidc.client_secrets(&client_id).await.expect("secrets"), []);
    let history = database
        .events()
        .history_for_client(&client_id, 1)
        .await
        .expect("history");
    assert_eq!(
        (history[0].event.known(), &history[0].actor),
        (
            Some(&DomainEvent::ClientDeleted {
                client_id: client_id.clone()
            }),
            &Actor::User {
                user_id: alice.user_id,
                session_id: Some(alice.session_id),
            }
        )
    );

    let reused = ClientRegistration {
        id: client_id.clone(),
        ..registration(ClientKind::Confidential, "https://notes.example")
    };
    assert!(matches!(
        register(database, &reused).await,
        Err(ClientRegistryError::Exists { .. })
    ));
    let secret = Some(ClientSecret::generate().expect("secret"));
    assert!(matches!(
        change(database, async |registry| {
            registry
                .apply(&reused, secret, GracePeriod::default())
                .await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(database, async |registry| {
            registry.set_enabled(&client_id, true).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(database, async |registry| {
            registry.delete(&client_id).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
}

/// A deletion and a refresh rotation lock a family and the client in the same
/// order, so they never deadlock. Here a transaction holds one family of the
/// client while the deletion waits for it, then rotates another family, which
/// locks the client: the deletion must not be holding it yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_refresh_rotation_never_deadlock() {
    let granting = Granting::new().await;
    let (held, held_digest) = granting.grant(TokenId::new()).await;
    let (rotated, rotated_digest) = granting.grant(TokenId::new()).await;

    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .revoke_family_for_token(held, std::slice::from_ref(&held_digest))
        .await
        .expect("hold the first family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    holder
        .tokens()
        .consume_for_rotation(
            rotated,
            std::slice::from_ref(&rotated_digest),
            granting.client.as_str(),
        )
        .await
        .expect("the rotation locks the client while the deletion waits");
    holder.commit().await.expect("commit");
    deletion
        .await
        .expect("task")
        .expect("the deletion follows the rotation");

    let mut tx = granting.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(
                rotated,
                std::slice::from_ref(&rotated_digest),
                granting.client.as_str()
            )
            .await,
        Err(RefreshRotationError::Invalid | RefreshRotationError::Replay { .. })
    ));
}

/// A family granted after a deletion locked the client's families is locked by
/// no one else but a rotation that will find the client deleted, so the deletion
/// skips it instead of waiting, which could deadlock with that rotation. Here the
/// deletion queues behind a held family while the grant commits, then a second
/// transaction holds the new family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_skips_families_granted_while_it_waits() {
    let granting = Granting::new().await;
    let (held, fresh) = (TokenId::new(), TokenId::new());
    granting.grant(held).await;
    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(held)
        .await
        .expect("hold the family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    let (token, digest) = granting.grant(fresh).await;
    let mut rotation = granting.database.begin().await.expect("transaction");
    rotation
        .tokens()
        .lock_family(fresh)
        .await
        .expect("hold the fresh family");
    holder.commit().await.expect("commit");
    tokio::time::timeout(std::time::Duration::from_secs(10), deletion)
        .await
        .expect("the deletion does not wait for the fresh family")
        .expect("task")
        .expect("deletion");
    let id = granting.client.as_str();
    assert!(matches!(
        rotation
            .tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), id)
            .await,
        Err(RefreshRotationError::Invalid)
    ));
}

/// A deletion and a logout that share families lock them in the same order, so
/// they never deadlock. The families are inserted highest ID first, so a scan
/// meets them out of ID order; a transaction holds the lowest while the deletion,
/// then the logout, queue for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_logout_never_deadlock() {
    let granting = Granting::new().await;
    let (low, high) = (TokenId::new(), TokenId::new());
    for family in [high, low] {
        granting.grant(family).await;
    }

    let mut holder = granting.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(low)
        .await
        .expect("hold the lowest family");
    let deletion = granting.delete();
    until_blocked(&mut holder, 1).await;
    let logout = tokio::spawn({
        let database = granting.database.clone();
        let (user, session) = (granting.user.user_id, granting.user.session_id);
        async move {
            let mut tx = database.begin().await?;
            sign_out(&mut tx, user, session).await?;
            tx.commit().await
        }
    });
    until_blocked(&mut holder, 2).await;
    holder.commit().await.expect("commit");
    deletion.await.expect("task").expect("deletion");
    logout.await.expect("task").expect("logout");
}
