//! Undoing a recovery: who may, what it takes back, and what the pages read of it.

use super::*;
use crate::{passkey::VerifiedRecoveryUndo, tests::until_blocked};
use sourceorigin_common::events::SignInFailure;

/// Undoing a recovery in probation, with a passkey from before it and no
/// session, takes back what whoever used its link could keep: its passkey, every
/// session and refresh grant, and every consent, old and new. It signs the
/// undoing browser in, and leaves nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_takes_back_the_passkey_sessions_grants_and_consents() {
    let mut scenario = Scenario::new().await;
    scenario.consent("https://notes.example").await;
    let token = scenario.recover().await;
    let cookie = scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let recovered = recovery.passkey_id.expect("its passkey");
    let probation_session = scenario.session(&cookie).await.expect("session").id;
    let client = scenario.consent("https://photos.example").await;
    let family = TokenId::new();
    refresh_grant(
        scenario.database(),
        scenario.user(),
        probation_session,
        &client,
        family,
    )
    .await;

    let status = scenario.status(&cookie).await;
    assert_eq!(status["state"], "probation");
    assert_eq!(status["passkey"]["id"], json!(recovered));
    let undo_with: Vec<_> = status["undo_with"]
        .as_array()
        .expect("undo_with")
        .iter()
        .map(|passkey| passkey["id"].clone())
        .collect();
    assert_eq!(undo_with, [json!(scenario.keys.key_id)]);

    let (status, body, signed_in) = scenario.undo(recovery.id).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    assert_eq!(
        scenario.passkeys().await,
        HashSet::from([scenario.keys.key_id])
    );
    assert!(scenario.consents().await.is_empty(), "every consent");
    assert!(scenario.session(&cookie).await.is_none(), "signed out");
    let mut tokens = scenario.database().tokens();
    let grants = tokens.revoke_for_user(scenario.user(), None).await;
    assert_eq!(grants.expect("grants"), 0, "already revoked");
    let events = scenario.events().await;
    assert!(events.contains(&DomainEvent::PasskeyRemoved {
        passkey_id: recovered
    }));
    assert!(events.contains(&DomainEvent::RecoveryUndone {
        recovery_id: recovery.id
    }));
    let signed_in = signed_in.expect("signed in");
    assert_eq!(
        scenario.status(&signed_in).await,
        Value::Null,
        "nothing left"
    );
}

/// An undo and a client's deletion lock the account's refresh families before
/// its consents, so they never deadlock. Here a transaction locks the client's
/// families, as a deletion does first, while the undo waits for them, then
/// deletes the client and its consents: the undo must not be holding them yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_undo_and_a_client_deletion_never_deadlock() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let cookie = scenario.enroll(&token).await;
    let session = scenario.session(&cookie).await.expect("session").id;
    let client = scenario.consent("https://photos.example").await;
    let (database, user) = (scenario.database(), scenario.user());
    refresh_grant(database, user, session, &client, TokenId::new()).await;

    let mut holder = database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_client_families(std::slice::from_ref(&client))
        .await
        .expect("hold the client's families");
    let undo = tokio::spawn({
        let admin = scenario.admin();
        async move { admin.undo_recovery(&cli(), user, recovery_reason()).await }
    });
    until_blocked(&mut holder, 1).await;
    holder
        .oidc()
        .delete_client(&client)
        .await
        .expect("the undo holds no consent yet");
    holder.commit().await.expect("commit");
    undo.await
        .expect("task")
        .expect("the undo follows the deletion");
    assert!(scenario.consents().await.is_empty(), "every consent");
}

/// The pages read the account's recovery that can still be undone by its owner's
/// session, or by its ID alone, a disabled account's too: its stage, the passkey
/// its link enrolled, by ID and enrollment time only, and whether a passkey from
/// before it can undo it. Neither finds one that settled, nor an unknown one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_read_an_undoable_recovery_by_session_or_id() {
    let mut scenario = Scenario::new().await;
    let service = AccountService::new(scenario.database().clone());
    let token = scenario.recover().await;
    let owner = Browser::sign_in(scenario.database(), scenario.user())
        .await
        .owner(scenario.database())
        .await;
    let read = async |id: RecoveryId| {
        let by_session = service
            .recovery_notice(&(&owner).into())
            .await
            .expect("by session");
        let by_id = service.undoable_recovery(id).await.expect("by ID");
        assert_eq!(by_session, by_id, "the same either way");
        by_id
    };
    let recovery = scenario.latest().await;
    let open = RecoveryNotice {
        id: recovery.id,
        started_at: recovery.started_at,
        stage: RecoveryStage::Open {
            expires_at: recovery.expires_at,
        },
        undoable: true,
    };
    assert_eq!(read(recovery.id).await, Some(open));

    scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let passkey = recovery.passkey_id.expect("its passkey");
    let passkeys = scenario
        .database()
        .passkeys()
        .list_active(scenario.user())
        .await;
    let created_at = passkeys
        .expect("passkeys")
        .into_iter()
        .find(|stored| stored.id == passkey)
        .expect("active")
        .created_at;
    let probation = RecoveryNotice {
        stage: RecoveryStage::Probation {
            completed_at: recovery.completed_at.expect("completed"),
            settles_at: recovery.settles_at.expect("in probation"),
            passkey: Some(EnrolledPasskey {
                id: passkey,
                created_at,
            }),
        },
        ..open
    };
    assert_eq!(read(recovery.id).await, Some(probation));
    let disabled = scenario
        .database()
        .users()
        .set_status(scenario.user(), AccountStatus::Disabled)
        .await;
    assert!(disabled.expect("disable"));
    assert_eq!(
        service.undoable_recovery(recovery.id).await.expect("by ID"),
        Some(probation),
        "disabled"
    );

    let unknown = service.undoable_recovery(RecoveryId::new()).await;
    assert_eq!(unknown.expect("by ID"), None, "unknown");
    let mut recoveries = scenario.database().recoveries();
    recoveries
        .backdate_completion(recovery.id, PROBATION)
        .await
        .expect("settle");
    assert_eq!(read(recovery.id).await, None, "settled");
}

/// Only a passkey other than the recovery's own undoes it: the undo challenges
/// every other active one, a passkey enrolled during the probation by a session
/// an older passkey confirmed included, never the recovery's own, which the undo
/// refuses again under the lock. It finds nothing to undo once the recovery
/// settled, or for an unknown recovery.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_another_passkey_undoes_a_recovery() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let recovered = recovery.passkey_id.expect("its passkey");

    let mut tx = scenario.database().begin().await.expect("transaction");
    let undo = VerifiedRecoveryUndo::unverified(scenario.user(), recovery.id, recovered);
    let refused = AccountService::undo_recovery(&mut tx, RequestContext::TEST, &undo).await;
    assert!(
        matches!(
            refused,
            Err(AccountError::Recovery(RecoveryError::OlderPasskeyRequired))
        ),
        "the recovery's own passkey"
    );
    drop(tx);

    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let (started, browser) = scenario
        .keys
        .start("/account/passkeys/enroll/start", &confirmed, json!({}))
        .await;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.credential(&started),
        "friendly_name": "Added during probation",
    });
    let cookies = format!("{confirmed}; {browser}");
    let response = scenario
        .keys
        .request(
            "/account/passkeys/enroll/finish",
            Method::POST,
            &cookies,
            body,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (started, _) = scenario.undo_start(recovery.id).await.expect("undo");
    let allowed = started["public_key"]["publicKey"]["allowCredentials"]
        .as_array()
        .map(Vec::len);
    assert_eq!(allowed, Some(2), "every passkey but the recovery's");
    assert_eq!(scenario.passkeys().await.len(), 3);

    let (status, ..) = scenario.undo(RecoveryId::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown");
    let mut recoveries = scenario.database().recoveries();
    recoveries
        .backdate_completion(recovery.id, PROBATION)
        .await
        .expect("settle");
    let (status, ..) = scenario.undo(recovery.id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "settled");
}

/// Undoing a recovery whose link was not used only cancels the link: nobody got
/// in with it, so sessions and consents stay. An undo applies only to the
/// recovery its ceremony named.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undoing_an_unused_link_only_cancels_it() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let elsewhere = scenario.signed_in_with(scenario.keys.key_id).await;
    scenario.consent("https://notes.example").await;

    let recovery = scenario.latest().await;
    let (status, body, _) = scenario.undo(recovery.id).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    assert!(!scenario.works(&token).await, "cancelled");
    assert!(
        scenario.session(&elsewhere).await.is_some(),
        "still signed in"
    );
    assert_eq!(scenario.consents().await.len(), 1, "consent kept");

    // An undo started for a recovery that a newer one replaced before it
    // finished undoes nothing: the proof names the recovery it was started for.
    scenario.recover().await;
    let replaced = scenario.latest().await.id;
    let (started, browser) = scenario.undo_start(replaced).await.expect("undo");
    let token = scenario.recover().await;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.assertion(&started),
    });
    let response = scenario
        .keys
        .request(routes::recovery::UNDO_FINISH, Method::POST, &browser, body)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "replaced meanwhile"
    );
    assert!(scenario.works(&token).await, "the newer one stands");
}

/// The owner undoes a recovery of a disabled account, so asking support to
/// disable it cannot outlast the undo: it signs nobody in, and the account stays
/// disabled, refusing a sign-in started before it was disabled. Once enabled, the
/// older passkey signs in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_owner_undoes_a_disabled_accounts_recovery() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    scenario.enroll(&token).await;
    let recovery = scenario.latest().await.id;
    // A sign-in started before the account is disabled.
    let body = json!({ "handle": scenario.keys.username });
    let login = scenario
        .keys
        .start("/webauthn/authenticate/start", "", body)
        .await;
    // Written as a release older than this one would, which knows nothing of
    // recoveries.
    let disabled = scenario
        .database()
        .users()
        .set_status(scenario.user(), AccountStatus::Disabled)
        .await;
    assert!(disabled.expect("disable"));

    let (status, body, cookie) = scenario.undo(recovery).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": false }))
    );
    assert!(cookie.is_none(), "nobody signed in");
    assert_eq!(
        scenario.passkeys().await,
        HashSet::from([scenario.keys.key_id])
    );
    let user = scenario
        .database()
        .users()
        .find_by_id(scenario.user())
        .await;
    let status = user.expect("lookup").expect("user").status;
    assert_eq!(status, AccountStatus::Disabled, "still disabled");
    let (started, browser) = login;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.assertion(&started),
    });
    let response = scenario
        .keys
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            body,
        )
        .await;
    assert!(response.status().is_client_error(), "sign-in refused");
    let cookie = response.headers().get(axum::http::header::SET_COOKIE);
    assert!(cookie.is_none(), "no session");
    let refused = DomainEvent::SignInFailed {
        method: AuthenticationMethod::Passkey,
        reason: SignInFailure::AccountUnavailable,
    };
    assert!(scenario.events().await.contains(&refused), "recorded");

    scenario
        .admin()
        .enable_user(&cli(), scenario.user())
        .await
        .expect("enable");
    let response = scenario.login("").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "once enabled");
}

/// Support undoes a recovery for an owner with no passkey left from before it,
/// and takes back its passkey even when it is the account's last; support then
/// starts another recovery. The listing shows the undone one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn support_undoes_and_takes_the_last_passkey() {
    let mut scenario = Scenario::new().await;
    let address = scenario.address("address", true).await;
    let link = scenario
        .start(Some(Revoke::default()))
        .await
        .expect("recovery");
    let notice = ("account_secured".to_owned(), Some(false));
    assert_eq!(scenario.messages(address).await, [notice], "nothing kept");
    scenario.enroll(&recovery_token(&link)).await;
    assert_eq!(scenario.passkeys().await.len(), 1, "only the recovery's");
    let recovery = scenario.latest().await.id;

    scenario
        .admin()
        .undo_recovery(&cli(), scenario.user(), recovery_reason())
        .await
        .expect("support undoes");
    assert!(scenario.passkeys().await.is_empty(), "the last one too");
    let recent = scenario
        .admin()
        .recent_recoveries(&cli(), scenario.user())
        .await;
    let recent = recent.expect("recent");
    assert_eq!(recent[0].id, recovery);
    assert_eq!(recent[0].state, RecoveryState::Ended);
    assert!(recent[0].undone_at.is_some(), "listed as undone");
    scenario.recover().await;
}
