//! Operators renaming, releasing and checking handles.

use super::*;
use crate::handles::HandlesError;
use piquel_common::HandleError;

/// A handle rename records its reason with the change, as personal data the
/// owner sees in their history.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn handle_renames_record_their_reason() {
    let harness = Harness::new().await;
    let suffix = &TokenId::new().to_string()[24..];
    let account = harness.named(&format!("before-{suffix}")).await;
    let after = Handle::parse(&format!("after-{suffix}")).expect("handle");
    harness
        .service()
        .rename_handle(&cli(), account, after, reason("Impersonation"), false)
        .await
        .expect("rename");
    let latest = harness.database.events().history_for_user(account, 1).await;
    let latest = latest.expect("history");
    assert_eq!(latest[0].reason.as_deref(), Some("Impersonation"));
}

/// Operators rename without the cooldown, but not to a taken, retired, look-alike,
/// reserved or unchanged handle. A released handle stays its former owner's until
/// an operator releases it; `handle check` lists reserved handles operators assign.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn operators_rename_and_release_handles() {
    let harness = Harness::new().await;
    let service = harness.service();
    let suffix = &TokenId::new().to_string()[24..];
    let handle = |name: &str| Handle::parse(&format!("{name}-{suffix}")).expect("handle");
    let first = harness.named(handle("first").as_str()).await;
    let second = harness.named(handle("second").as_str()).await;
    let rename = |user, handle: Handle, allow_reserved| {
        let service = service.clone();
        async move {
            service
                .rename_handle(&cli(), user, handle, reason("Renamed"), allow_reserved)
                .await
        }
    };
    let refused = |result: Result<(), AdminError>| match result {
        Err(AdminError::Handle(error)) => error,
        other => panic!("not a handle refusal: {other:?}"),
    };
    assert!(matches!(
        refused(rename(second, handle("first"), false).await),
        HandlesError::Taken
    ));
    assert!(matches!(
        refused(rename(second, Handle::parse(&format!("f1rst{suffix}")).expect("handle"), false).await),
        HandlesError::Confusable(other) if other == handle("first")
    ));
    assert!(matches!(
        refused(rename(second, Handle::parse("adm1n").expect("handle"), false).await),
        HandlesError::Refused(HandleError::Reserved(_))
    ));
    assert!(matches!(
        refused(rename(second, handle("second"), false).await),
        HandlesError::Current
    ));
    rename(second, handle("renamed"), false)
        .await
        .expect("rename");
    let renamed = harness
        .database
        .users()
        .find_by_id(second)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(renamed.handle, handle("renamed"));
    assert_eq!(renamed.profile_version, 2);
    assert_eq!(
        harness.events(second).await[..1],
        [DomainEvent::HandleChanged {
            old: Personal::Value(handle("second").to_string()),
            new: Personal::Value(handle("renamed")),
        }]
    );
    // The old handle stays the second account's: the first cannot take it, but
    // its owner can, at once, as operators skip the cooldown.
    assert!(matches!(
        refused(rename(first, handle("second"), false).await),
        HandlesError::Retired
    ));
    rename(second, handle("second"), false)
        .await
        .expect("reclaim");
    assert!(matches!(
        service.release_handle(&cli(), handle("second")).await,
        Err(AdminError::HandleNotReleased)
    ));
    service
        .release_handle(&cli(), handle("renamed"))
        .await
        .expect("release");
    assert_eq!(
        harness.events(second).await[..1],
        [DomainEvent::HandleReleased {
            handle: Personal::Value(handle("renamed")),
        }]
    );
    rename(first, handle("renamed"), false)
        .await
        .expect("a released handle is free");
    // A reserved handle is listed while an account holds it.
    let reserved = Handle::parse("piquel").expect("handle");
    let listed = || async {
        service
            .check_handles(&cli())
            .await
            .expect("check")
            .into_iter()
            .any(|problem| problem.user_id == first)
    };
    rename(first, reserved.clone(), true)
        .await
        .expect("reserved rename");
    assert!(listed().await);
    rename(first, handle("first"), false)
        .await
        .expect("reclaim");
    assert!(!listed().await);
    service
        .release_handle(&cli(), reserved)
        .await
        .expect("release");
}
