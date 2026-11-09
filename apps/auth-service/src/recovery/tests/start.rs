//! Starting a recovery: what a start replaces and refuses, `--revoke`, and a disabled email.

use super::*;
use sourceorigin_common::events::RecoveryRevocation;

/// A start is refused while a recovery is in probation, for a disabled account,
/// and for an administrator; it replaces an unused link, expired or not. Only an
/// operator at the terminal starts one that would not be mailed. Disabling an
/// account cancels its unused link.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn what_a_start_replaces_and_refuses() {
    let mut scenario = Scenario::new().await;
    let first = scenario.recover().await;
    let second = scenario.recover().await;
    assert!(!scenario.works(&first).await, "replaced");
    assert!(scenario.works(&second).await);
    let expired = scenario.latest().await.id;
    let mut recoveries = scenario.database().recoveries();
    recoveries.expire(expired).await.expect("expire");
    let third = scenario.recover().await;
    scenario.enroll(&third).await;
    let refused = scenario.start(None).await;
    assert!(matches!(refused, Err(AdminError::RecoveryInProbation)));

    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let admin_id = admin.user_id;
    let administrator = operator(admin, Utc::now());
    let account = harness.account().await.user_id;
    let service = AdminService::new(harness.database.clone(), true);
    let links = recovery_links();
    let unmailed = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert!(
        matches!(unmailed, Err(AdminError::RecoveryNeedsEmail)),
        "no address"
    );
    let address = format!("{account}@example.com");
    verified_address(&harness.database, account, &address, true).await;
    let revoked = service
        .recover_account(
            &administrator,
            account,
            recovery_reason(),
            &links,
            Some(Revoke::default()),
        )
        .await;
    assert!(
        matches!(revoked, Err(AdminError::RecoveryNeedsEmail)),
        "printed only"
    );
    let mailed = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert_eq!(
        mailed.expect("mailed"),
        None,
        "an administrator never sees it"
    );
    let to_admin = service
        .recover_account(&cli(), admin_id, recovery_reason(), &links, None)
        .await;
    assert!(matches!(to_admin, Err(AdminError::RecoveryOfAdministrator)));

    let link = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await
        .expect("recovery")
        .expect("link");
    service
        .disable_user(&cli(), account, recovery_reason())
        .await
        .expect("disable");
    let disabled = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await;
    assert!(matches!(
        disabled,
        Err(AdminError::RecoveryOfDisabledAccount)
    ));
    service.enable_user(&cli(), account).await.expect("enable");
    let accounts = AccountService::new(harness.database.clone());
    let opened = accounts.open_recovery(&recovery_token(&link)).await;
    assert!(
        opened.is_err(),
        "disabling cancelled it, so enabling does not revive it"
    );
}

/// While email is disabled, a recovery whose link would only be mailed is
/// refused before anything changes: the account keeps its session, and nothing
/// starts. The terminal, which prints its link, still recovers it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn no_recovery_starts_while_email_is_disabled() {
    let harness = Harness::new().await;
    let administrator = operator(harness.admin().await, Utc::now());
    let owner = harness.account().await;
    let account = owner.user_id;
    let address = format!("{account}@example.com");
    verified_address(&harness.database, account, &address, true).await;
    let service = AdminService::new(harness.database.clone(), false);
    let links = recovery_links();
    let refused = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert!(matches!(refused, Err(AdminError::RecoveryNeedsEmail)));
    let session = harness
        .database
        .sessions()
        .find_by_id(owner.session_id)
        .await
        .expect("lookup")
        .expect("session");
    assert!(session.revoked_at.is_none(), "still signed in");
    let recent = service
        .recent_recoveries(&cli(), account)
        .await
        .expect("recoveries");
    assert!(recent.is_empty(), "nothing started");
    let printed = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await
        .expect("recovery");
    assert!(printed.is_some(), "the terminal prints its link");
}

/// A recovery started with `--revoke` takes back every way in but the kept
/// passkeys, in its own transaction: every other passkey, every identity and
/// every consent. Its link is only printed, and every verified address hears of
/// it at once. A kept passkey can still cancel it. A kept passkey the account
/// does not have fails the whole start.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoke_takes_back_every_way_in_but_the_kept_passkeys() {
    let mut scenario = Scenario::new().await;
    let stolen = scenario.keys.key_id;
    let primary = scenario.address("primary", true).await;
    let other = scenario.address("other", false).await;
    // The owner's other passkey, which signs from now on.
    let kept = scenario.keys.switch_passkey("Kept").await;
    scenario.link(Provider::GitHub).await;
    scenario.consent("https://notes.example").await;
    // A link already sent does not stand in the way.
    scenario.recover().await;

    let unknown = Revoke {
        keep: vec![PasskeyId::new()],
    };
    let refused = scenario.start(Some(unknown)).await;
    assert!(matches!(refused, Err(AdminError::UnknownPasskey(_))));
    assert_eq!(scenario.passkeys().await, HashSet::from([kept, stolen]));

    let (primary_before, other_before) = (scenario.sent(primary).await, scenario.sent(other).await);
    scenario
        .start(Some(Revoke { keep: vec![kept] }))
        .await
        .expect("recovery");
    assert_eq!(scenario.passkeys().await, HashSet::from([kept]));
    assert!(
        scenario.identities().await.is_empty(),
        "identities unlinked"
    );
    assert!(scenario.consents().await.is_empty(), "consents withdrawn");
    let recovery = scenario.latest().await.id;
    let started = scenario
        .events()
        .await
        .into_iter()
        .find_map(|event| match event {
            DomainEvent::RecoveryStarted {
                recovery_id,
                revoke,
                ..
            } if recovery_id == recovery => Some(revoke),
            _ => None,
        });
    let revocation = RecoveryRevocation {
        revoked: vec![stolen],
        kept: vec![kept],
    };
    assert_eq!(started, Some(Some(revocation)), "recorded on the start");
    assert_eq!(
        (
            scenario.sent(primary).await - primary_before,
            scenario.sent(other).await - other_before,
        ),
        (1, 1),
        "a notice to every verified address, and no link"
    );
    let notice = ("account_secured".to_owned(), Some(true));
    assert_eq!(scenario.messages(other).await.last(), Some(&notice), "kept");

    let (status, body, _) = scenario.undo(recovery).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    let cancelled = scenario.database().recoveries().find(recovery).await;
    let cancelled = cancelled.expect("lookup").expect("recovery").cancelled_at;
    assert!(cancelled.is_some(), "the kept passkey cancelled it");
}
