//! Database-backed rename scenarios of the owner.

use super::*;
use crate::security::SessionError;
use crate::tests::{Browser, Replicas};
use piquel_common::AuthenticationMethod;

/// A rename needs a passkey confirmation, and the cooldown to have passed since the
/// last change, reclaims included. It bumps the profile version and records the
/// change.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn renames_wait_out_the_cooldown() {
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
    // A new account's handle has just been chosen.
    let Err(AccountError::Handle(HandlesError::Cooldown { retry_after })) =
        account.rename_handle(&owner, &renamed).await
    else {
        panic!("a new handle is in its cooldown");
    };
    assert_eq!(retry_after, original.handle_changed_at + COOLDOWN);

    wait_out_cooldown().await;
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
    assert!(matches!(
        account
            .rename_handle(&owner, original.handle.as_str())
            .await,
        Err(AccountError::Handle(HandlesError::Cooldown { .. }))
    ));

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
