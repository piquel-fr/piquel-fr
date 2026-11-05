//! A picture's lifecycle against the schema: what its URL serves, and the profile
//! version every change bumps.
use crate::{Database, InsertUser};
use piquel_common::{AccountStatus, PictureId};

/// A replaced picture's ID serves nothing and the new one serves its bytes; a
/// disabled account serves none, and its records name none; removing it clears
/// the account's picture. Each
/// change bumps the profile version once.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_picture_serves_only_while_current_and_active() {
    let database = Database {
        pool: Database::test_pool().await,
    };
    let account = InsertUser::named("picture");
    database.users().insert(&account).await.expect("user");
    let user = async || {
        database
            .users()
            .find_by_id(account.id)
            .await
            .expect("read")
            .expect("user")
    };
    assert_eq!(
        (user().await.picture, user().await.profile_version),
        (None, 1)
    );

    let (first, second) = (PictureId::new(), PictureId::new());
    let set = database
        .pictures()
        .set(account.id, first, b"first")
        .await
        .expect("set");
    assert_eq!(set.id, first);
    database
        .pictures()
        .set(account.id, second, b"second")
        .await
        .expect("replace");
    assert_eq!(database.pictures().image(first).await.expect("old"), None);
    assert_eq!(
        database
            .pictures()
            .image(second)
            .await
            .expect("new")
            .as_deref(),
        Some(&b"second"[..]),
    );
    assert_eq!(
        (user().await.picture, user().await.profile_version),
        (Some(second), 3)
    );

    database
        .users()
        .set_status(account.id, AccountStatus::Disabled)
        .await
        .expect("disable");
    assert_eq!(
        database.pictures().image(second).await.expect("disabled"),
        None
    );
    // Nor does any record of it name one that would not load.
    assert_eq!(user().await.picture, None);
    let found = database
        .users()
        .search(&account.id.to_string(), 0, 1)
        .await
        .expect("search");
    assert_eq!(found[0].picture, None);
    database
        .users()
        .set_status(account.id, AccountStatus::Active)
        .await
        .expect("enable");

    assert!(
        database
            .pictures()
            .remove(account.id)
            .await
            .expect("remove")
    );
    assert!(!database.pictures().remove(account.id).await.expect("again"));
    assert_eq!(
        database.pictures().image(second).await.expect("removed"),
        None
    );
    assert_eq!(
        (user().await.picture, user().await.profile_version),
        (None, 4)
    );
}
