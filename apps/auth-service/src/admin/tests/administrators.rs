//! Granting and revoking administrator rights, and the protections around them.

use super::*;
use crate::deletion::DeletionError;
use crate::tests::{recovery_links, recovery_reason};

/// Administrator accounts are out of the dashboard's reach until their rights
/// are revoked, and nobody grants or revokes their own rights there. A
/// revocation applies to the revoked administrator's next request.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_are_protected_until_revoked() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let other = harness.account().await;
    let (by_admin, by_other) = (operator(admin, Utc::now()), operator(other, Utc::now()));
    service
        .grant_administrator(&by_admin, other.user_id)
        .await
        .expect("grant");
    service
        .search_users(&by_other, "", None)
        .await
        .expect("the new administrator reads");
    let refused = service
        .disable_user(&by_admin, other.user_id, reason("Compromised"))
        .await;
    assert!(
        matches!(refused, Err(AdminError::AdministratorTarget)),
        "{refused:?}"
    );
    let refused = service.revoke_administrator(&by_admin, admin.user_id).await;
    assert!(matches!(refused, Err(AdminError::OwnRights)), "{refused:?}");
    // Refused before any lock, so a grant queued behind the caller's own
    // revocation cannot restore their rights.
    let refused = service.grant_administrator(&by_admin, admin.user_id).await;
    assert!(matches!(refused, Err(AdminError::OwnRights)), "{refused:?}");
    service
        .revoke_administrator(&by_admin, other.user_id)
        .await
        .expect("revoke");
    let refused = service.search_users(&by_other, "", None).await;
    assert!(
        matches!(refused, Err(AdminError::NotAdministrator)),
        "{refused:?}"
    );
    service
        .disable_user(&by_admin, other.user_id, reason("Compromised"))
        .await
        .expect("disable");
    assert_eq!(
        harness.events(other.user_id).await[2..4],
        [
            DomainEvent::AdministratorRevoked {},
            DomainEvent::AdministratorGranted {},
        ][..]
    );
}

/// Two administrators acting on each other at once are both refused, rather than
/// deadlocking on each other's account lock.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_acting_on_each_other_are_refused() {
    let harness = Harness::new().await;
    let service = harness.service();
    let (a, b) = (harness.admin().await, harness.admin().await);
    for _ in 0..10 {
        let disable = |by: Account, target: Account| {
            let service = service.clone();
            async move {
                let by = operator(by, Utc::now());
                service
                    .disable_user(&by, target.user_id, reason("Rogue"))
                    .await
            }
        };
        let (first, second) = tokio::join!(disable(a, b), disable(b, a));
        for refused in [first, second] {
            assert!(
                matches!(refused, Err(AdminError::AdministratorTarget)),
                "{refused:?}"
            );
        }
    }
}

/// Nothing, the CLI included, revokes, disables or deletes the last active
/// administrator; a disabled administrator does not count. Two such changes
/// queued on the administrator lock cannot both pass: the second sees the first.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_last_active_administrator_stays() {
    let harness = Harness::isolated().await;
    let (service, cli) = (harness.service(), cli());
    let (a, b) = (harness.admin().await, harness.admin().await);
    service
        .disable_user(&cli, b.user_id, reason("Away"))
        .await
        .expect("disable");
    let last = AdminError::LastAdministrator;
    let refusals = [
        (
            service.disable_user(&cli, a.user_id, reason("Away")).await,
            &last,
            "disable",
        ),
        (
            service
                .schedule_deletion(&cli, a.user_id, reason("Away"))
                .await,
            &AdminError::Deletion(DeletionError::LastAdministrator),
            "delete",
        ),
        (
            service.revoke_administrator(&cli, a.user_id).await,
            &last,
            "revoke",
        ),
    ];
    for (refused, expected, case) in refusals {
        assert_refused(&refused.expect_err(case), expected, case);
    }

    service.enable_user(&cli, b.user_id).await.expect("enable");
    let mut held = harness.database.begin().await.expect("transaction");
    held.administrators().lock().await.expect("lock");
    let (disabled, revoked, ()) = tokio::join!(
        service.disable_user(&cli, a.user_id, reason("Away")),
        service.revoke_administrator(&cli, b.user_id),
        async {
            until_blocked(&mut held, 2).await;
            held.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(
            (&disabled, &revoked),
            (Ok(()), Err(AdminError::LastAdministrator))
                | (Err(AdminError::LastAdministrator), Ok(()))
        ),
        "{disabled:?}, {revoked:?}"
    );
}

/// Nobody is made an administrator while a recovery of the account can still be
/// undone, not even from the CLI: granted during its probation, the rights would
/// go live for whoever used its link once it settles. Once support undid it,
/// nothing is left to refuse.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn no_grant_while_a_recovery_can_be_undone() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let target = harness.account().await.user_id;
    let service = harness.service();
    service
        .recover_account(&cli(), target, recovery_reason(), &recovery_links(), None)
        .await
        .expect("recovery");

    let refused = service
        .grant_administrator(&operator(admin, Utc::now()), target)
        .await;
    assert!(
        matches!(refused, Err(AdminError::GrantDuringRecovery)),
        "the dashboard refuses"
    );
    let refused = service.grant_administrator(&cli(), target).await;
    assert!(
        matches!(refused, Err(AdminError::GrantDuringRecovery)),
        "the CLI too"
    );
    let granted = harness.database.administrators().contains(target).await;
    assert!(!granted.expect("rights"), "not granted");

    service
        .undo_recovery(&cli(), target, recovery_reason())
        .await
        .expect("support cancels the unused link");
    service
        .grant_administrator(&cli(), target)
        .await
        .expect("granted once nothing can be undone");
}
