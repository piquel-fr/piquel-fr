//! Database-backed rename scenarios of the owner.

use super::*;
use crate::security::SessionError;
use crate::tests::{Browser, Replicas};
use sourceorigin_common::AuthenticationMethod;

/// A rename needs a passkey confirmation. A new account may change its handle at
/// once; every later change, reclaims included, waits out the cooldown since the
/// last one. A rename bumps the profile version and records the change.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_first_rename_is_free_and_later_ones_wait_out_the_cooldown() {
    let database = Replicas::database().await;
    let account = AccountService::new(database.clone());
    let browser = Browser::new_account(&database).await;
    let owner = browser.owner(&database).await;
    let user = async || {
        database
            .users()
            .find_by_id(browser.user_id)
            .await
            .expect("lookup")
            .expect("user")
    };
    let wait_out_cooldown = async || {
        database
            .users()
            .age_handle_change(browser.user_id, 31)
            .await
            .expect("age");
    };
    let original = user().await;
    let renamed = format!("renamed-{}", &browser.user_id.to_string()[24..]);

    // Social sign-in never confirms a session.
    let social =
        Browser::sign_in_with(&database, browser.user_id, AuthenticationMethod::Federation)
            .await
            .owner(&database)
            .await;
    assert!(matches!(
        account.rename_handle(&social, &renamed).await,
        Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
    ));
    // A new account corrects the handle chosen at signup without waiting.
    assert_eq!(original.handle_changed_at, None);
    let handle = account
        .rename_handle(&owner, &format!(" {renamed} "))
        .await
        .expect("rename");
    assert_eq!(handle.as_str(), renamed);
    let changed = user().await;
    assert_eq!(changed.handle, handle);
    assert_eq!(changed.profile_version, original.profile_version + 1);
    let history = database
        .events()
        .history_for_user(browser.user_id, 1)
        .await
        .expect("history");
    assert_eq!(
        history[0].event.known(),
        Some(&DomainEvent::HandleChanged {
            old: Personal::Value(original.handle.to_string()),
            new: Personal::Value(handle),
        })
    );
    let Err(AccountError::Handle(HandlesError::Cooldown { retry_after })) = account
        .rename_handle(&owner, original.handle.as_str())
        .await
    else {
        panic!("the second change waits out the cooldown");
    };
    assert_eq!(
        Some(retry_after),
        changed.handle_changed_at.map(|at| at + COOLDOWN)
    );

    // Taking back the old handle restarts the cooldown too.
    wait_out_cooldown().await;
    account
        .rename_handle(&owner, original.handle.as_str())
        .await
        .expect("reclaim");
    assert!(matches!(
        account.rename_handle(&owner, &renamed).await,
        Err(AccountError::Handle(HandlesError::Cooldown { .. }))
    ));
}
