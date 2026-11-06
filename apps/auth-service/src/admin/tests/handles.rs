//! Operators renaming, releasing and checking handles.

use super::*;
use crate::handles::HandlesError;
use piquel_common::HandleError;

/// Operators rename without the cooldown, but not to a taken, retired, look-alike,
/// reserved or unchanged handle, and the rename records their reason, as personal
/// data the owner sees in their history. A released handle stays its former
/// owner's until an operator releases it; `handle check` lists reserved handles
/// operators assign.
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
    let renamed = harness.database.users().find_by_id(second).await;
    let renamed = renamed.expect("lookup").expect("user");
    assert_eq!(renamed.handle, handle("renamed"));
    assert_eq!(renamed.profile_version, 2);
    let latest = harness.database.events().history_for_user(second, 1).await;
    let latest = &latest.expect("history")[0];
    assert_eq!(latest.reason.as_deref(), Some("Renamed"));
    assert_eq!(
        latest.event.known(),
        Some(&DomainEvent::HandleChanged {
            old: Personal::Value(handle("second").to_string()),
            new: Personal::Value(handle("renamed")),
        })
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

/// An administrator reserves a handle for someone: nobody takes it, or a
/// look-alike, at signup or in the settings, until an administrator gives it to
/// an account, which `handle check` then lists; removed from the list, anyone may
/// take it. Built-in names and look-alikes of reserved ones are not reserved twice.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_reserve_handles_until_they_give_them_out() {
    let harness = Harness::new().await;
    let service = harness.service();
    let suffix = &TokenId::new().to_string()[24..];
    let kept = Handle::parse(&format!("kept-{suffix}")).expect("handle");
    let look_alike = Handle::parse(&format!("kept{suffix}")).expect("handle");
    let handles = crate::handles::Handles::new(&harness.database);
    let reserved = |result: Result<(), HandlesError>| matches!(result, Err(HandlesError::Refused(HandleError::Reserved(name))) if name == kept.as_str());
    assert!(handles.ensure_unreserved(&kept).await.is_ok());
    service
        .reserve_handle(&cli(), kept.clone(), reason("For the new CTO"))
        .await
        .expect("reserve");
    assert!(reserved(handles.ensure_unreserved(&kept).await));
    assert!(reserved(handles.ensure_unreserved(&look_alike).await));
    for again in [
        kept.clone(),
        look_alike,
        Handle::parse("support").expect("handle"),
    ] {
        assert!(matches!(
            service.reserve_handle(&cli(), again, reason("Again")).await,
            Err(AdminError::HandleReserved)
        ));
    }
    let listed = service.list_reserved_handles(&cli()).await.expect("list");
    let reservation = listed
        .iter()
        .find(|reservation| reservation.handle == kept)
        .expect("listed");
    assert_eq!(reservation.reason, "For the new CTO");

    let user = harness.named(&format!("cto-{suffix}")).await;
    let give = |allow_reserved| {
        let (service, kept) = (service.clone(), kept.clone());
        async move {
            service
                .rename_handle(
                    &cli(),
                    user,
                    kept,
                    reason("Reserved for them"),
                    allow_reserved,
                )
                .await
        }
    };
    assert!(matches!(
        give(false).await,
        Err(AdminError::Handle(HandlesError::Refused(
            HandleError::Reserved(_)
        )))
    ));
    give(true).await.expect("given");
    let problems = service.check_handles(&cli()).await.expect("check");
    assert!(problems.iter().any(|problem| problem.user_id == user));

    service
        .unreserve_handle(&cli(), kept.clone())
        .await
        .expect("unreserve");
    assert!(matches!(
        service.unreserve_handle(&cli(), kept.clone()).await,
        Err(AdminError::HandleNotReserved)
    ));
    assert!(handles.ensure_unreserved(&kept).await.is_ok());
    let problems = service.check_handles(&cli()).await.expect("check");
    assert!(!problems.iter().any(|problem| problem.user_id == user));
}
