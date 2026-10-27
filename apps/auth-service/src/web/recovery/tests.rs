//! The recovery pages, and what the account's pages and its sign-ins ask of a
//! recovery, through the whole service, as a browser uses them.

use crate::{
    AdminService,
    recovery::PROBATION,
    routes::{
        oidc::AUTHORIZE_RESUME,
        page::{LOGIN, RECOVER, RECOVER_UNDO, settings},
    },
    security::{BrowserCookie, RequestContext},
    tests::{
        Browser, Replicas, location, operator, parameter, recovery_links, recovery_reason,
        recovery_token, redirect, register, registration, unusable_passkey,
    },
    web::tests::{authorize, cookie, html},
};
use axum::http::StatusCode;
use chrono::{DateTime, SecondsFormat, Utc};
use piquel_common::{
    EventId, RecoveryId, UserId,
    clients::{ClientKind, ClientRegistration},
    events::{Actor, DomainEvent},
};
use piquel_repository::{Database, InsertPasskey, StoredPasskey};
use piquel_ui::{
    HistoryChange, LoginChange, LoginQuery, Query, RecoverChange, SignInState, UndoChange,
};
use url::Position;

/// An account an operator at the terminal started recovering, which signed it out
/// everywhere.
struct Recovering {
    /// The test database.
    database: Database,
    /// The account.
    user_id: UserId,
    /// Its handle.
    handle: String,
    /// The recovery.
    id: RecoveryId,
    /// When its link stops working.
    expires_at: DateTime<Utc>,
    /// Its link's token.
    token: String,
    /// The history entry of the passkey from before, if any, which the account
    /// added.
    older: Option<EventId>,
}

impl Recovering {
    /// Recovers a new account, which keeps a passkey from before, `Existing key`,
    /// when `older`.
    async fn new(database: &Database, older: bool) -> Self {
        let user_id = Browser::new_account(database).await.user_id;
        let older = if older {
            Some(Self::add_older(database, user_id).await)
        } else {
            None
        };
        let link = AdminService::new(database.clone())
            .recover_account(
                &operator(),
                user_id,
                recovery_reason(),
                &recovery_links(),
                None,
            )
            .await
            .expect("recovery")
            .expect("the terminal sees the link");
        let latest = database.recoveries().latest(user_id).await;
        let latest = latest.expect("lookup").expect("recovery");
        let account = database.users().find_by_id(user_id).await;
        Self {
            database: database.clone(),
            user_id,
            handle: account.expect("lookup").expect("account").username,
            id: latest.id,
            expires_at: latest.expires_at,
            token: recovery_token(&link),
            older,
        }
    }

    /// Adds `Existing key` to the account `user_id`, as its own session would,
    /// and returns the history entry that records it.
    async fn add_older(database: &Database, user_id: UserId) -> EventId {
        let passkey = unusable_passkey(user_id);
        let added = DomainEvent::PasskeyAdded {
            passkey_id: passkey.id,
        };
        let context = RequestContext::TEST.actor(Actor::User {
            user_id,
            session_id: None,
        });
        let mut tx = database.begin().await.expect("transaction");
        tx.passkeys().insert(&passkey).await.expect("passkey");
        tx.record(&context, Some(user_id), added.clone())
            .await
            .expect("record");
        tx.commit().await.expect("commit");
        let history = database.events().history_for_user(user_id, 10).await;
        let history = history.expect("history");
        let entry = history
            .iter()
            .find(|stored| stored.event.known() == Some(&added));
        entry.expect("recorded").id
    }

    /// A browser signed in to the account since the recovery started.
    async fn signed_in(&self) -> Browser {
        Browser::sign_in(&self.database, self.user_id).await
    }

    /// Uses the link, enrolling a passkey that whoever used it then renamed to
    /// `name`, as the history records it, and returns the passkey.
    async fn enroll(&self, name: &str) -> StoredPasskey {
        let passkey = InsertPasskey {
            friendly_name: name.into(),
            ..unusable_passkey(self.user_id)
        };
        let id = passkey.id;
        let mut tx = self.database.begin().await.expect("transaction");
        let enrolled = tx.passkeys().insert(&passkey).await.expect("passkey");
        let completed = tx
            .recoveries()
            .complete(self.user_id, self.id, id, PROBATION)
            .await;
        assert!(completed.expect("complete"), "the link works");
        let context = RequestContext::TEST.actor(Actor::Anonymous);
        for event in [
            DomainEvent::PasskeyAdded { passkey_id: id },
            DomainEvent::PasskeyRenamed { passkey_id: id },
        ] {
            tx.record(&context, Some(self.user_id), event)
                .await
                .expect("record");
        }
        tx.commit().await.expect("commit");
        enrolled
    }
}

/// `at` as a page's `<time>` shows it, in UTC as `format` writes it.
fn time(at: DateTime<Utc>, format: &str) -> String {
    format!(
        r#"<time datetime="{}">{} UTC</time>"#,
        at.to_rfc3339_opts(SecondsFormat::Secs, true),
        at.format(format)
    )
}

/// The `strftime` format of a moment a page shows to the minute.
const MINUTE: &str = "%-d %b %Y %H:%M";

/// A recovery link's page never opens the link on its own: its form does, signed
/// out. A token that no longer works says why, and the link's own asks for a
/// passkey for its account until the link's deadline, saying up front what the
/// probation holds back. The token rides only in the passkey script's marker, so
/// the form never posts it again. Once the passkey script added the passkey, the
/// browser it signed in goes on to the settings.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn recovery_links_enroll_a_passkey_from_their_form() {
    let replicas = Replicas::new().await;
    let recovering = Recovering::new(&Replicas::database().await, true).await;
    let browser = Browser::signed_out();
    let page = browser.visit(&replicas.a, RECOVER).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = html(page).await;
    let fragment = r#"<input type="hidden" name="token" data-fragment="token">"#;
    assert!(page.contains(fragment), "{page}");
    assert!(page.contains("data-fragment-missing"), "{page}");

    let open = |token: &str| RecoverChange::Open {
        token: token.to_owned(),
    };
    let refused = browser.post(&replicas, RECOVER, &open("spent")).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(
        page.contains("This recovery link no longer works."),
        "{page}"
    );
    assert!(!page.contains("data-fragment-missing"), "{page}");

    let opened = browser
        .post(&replicas, RECOVER, &open(&recovering.token))
        .await;
    assert_eq!(opened.status(), StatusCode::OK);
    let page = html(opened).await;
    let heading = format!("Add a passkey to @{} (Browser test)", recovering.handle);
    assert!(page.contains(&heading), "{page}");
    let marker = format!(r#"data-passkey-recover="{}""#, recovering.token);
    assert!(page.contains(&marker), "{page}");
    assert!(!page.contains(r#"name="token""#), "{page}");
    let replaced = format!(r#"data-replace-url="{RECOVER}""#);
    assert!(page.contains(&replaced), "{page}");
    let until = format!(
        "This link works until {}.",
        time(recovering.expires_at, MINUTE)
    );
    assert!(page.contains(&until), "{page}");
    let probation = format!("For the next {} days,", PROBATION.num_days());
    assert!(page.contains(&probation), "{page}");

    let recovered = recovering
        .signed_in()
        .await
        .post(&replicas, RECOVER, &RecoverChange::Recovered {})
        .await;
    assert_eq!(redirect(&recovered), settings::HOME);
    assert_eq!(cookie(&recovered, BrowserCookie::Notice).0, "recovered");
    let signed_out = browser
        .post(&replicas, RECOVER, &RecoverChange::Recovered {})
        .await;
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&signed_out), LOGIN);
}

/// The undo page never undoes on its own: its form names the recovery, signed out,
/// and the page says what undoing it takes back at its stage, naming its passkey by
/// enrollment time and ID only, then offers the ceremony. Without a passkey from
/// before, only support can undo it, and an unknown recovery leaves nothing to
/// undo. Signed in, the page offers the account's own recovery should the link name
/// none. Once the passkey script undid it, a browser the undo signed in goes on to
/// the settings, and one it did not is told why, whatever session it holds.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_undo_page_cancels_or_undoes_by_id() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let recovering = Recovering::new(&database, true).await;
    let browser = Browser::signed_out();
    let page = html(browser.visit(&replicas.a, RECOVER_UNDO).await).await;
    let fragment = r#"<input type="hidden" name="recovery" data-fragment="recovery">"#;
    assert!(page.contains(fragment), "{page}");
    assert!(page.contains("This link is incomplete"), "{page}");

    let open = |recovery| UndoChange::Open { recovery };
    let marker = format!(r#"data-passkey-undo="{}""#, recovering.id);
    let outcome = r#"<input type="hidden" name="action" value="undone"><input type="hidden" name="signed_in" value="false">"#;
    let named = open(Some(recovering.id));
    let page = html(browser.post(&replicas, RECOVER_UNDO, &named).await).await;
    assert!(page.contains("Cancel this recovery?"), "{page}");
    assert!(page.contains("a recovery of your account"), "{page}");
    assert!(
        page.contains("If the link is used before you cancel, cancelling takes back"),
        "{page}"
    );
    assert!(page.contains(&marker), "{page}");
    assert!(page.contains(outcome), "{page}");

    let passkey = recovering.enroll("Sneaky name").await;
    let shown = browser.post(&replicas, RECOVER_UNDO, &named).await;
    assert_eq!(shown.status(), StatusCode::OK);
    let page = html(shown).await;
    assert!(page.contains("Undo this recovery?"), "{page}");
    let added = format!(
        "The passkey the recovery added on {}, ID {}</li>",
        time(passkey.created_at, MINUTE),
        passkey.id
    );
    assert!(page.contains(&added), "{page}");
    assert!(!page.contains("Sneaky name"), "{page}");
    assert!(page.contains(outcome), "{page}");

    let signed_in = recovering.signed_in().await;
    let page = html(signed_in.visit(&replicas.a, RECOVER_UNDO).await).await;
    let account = format!("a recovery link added a passkey to @{}", recovering.handle);
    assert!(page.contains(&account), "{page}");
    assert!(page.contains(&marker), "{page}");

    for recovery in [Some(RecoveryId::new()), None] {
        let nothing = browser.post(&replicas, RECOVER_UNDO, &open(recovery)).await;
        assert_eq!(nothing.status(), StatusCode::NOT_FOUND, "{recovery:?}");
        assert!(html(nothing).await.contains("nothing to undo"));
    }
    let unaided = Recovering::new(&database, false).await;
    let unaided = open(Some(unaided.id));
    let page = html(browser.post(&replicas, RECOVER_UNDO, &unaided).await).await;
    assert!(page.contains("only Piquel support can undo it"), "{page}");
    assert!(!page.contains("data-passkey-undo"), "{page}");

    let undone = |signed_in| UndoChange::Undone { signed_in };
    let answered = signed_in.post(&replicas, RECOVER_UNDO, &undone(true)).await;
    assert_eq!(redirect(&answered), settings::HOME);
    assert_eq!(
        cookie(&answered, BrowserCookie::Notice).0,
        "recovery_undone"
    );
    // An undo that signed nobody in says so even in a browser holding another
    // account's session.
    let other = Browser::new_account(&database).await;
    for holder in [&browser, &other] {
        let done = holder.post(&replicas, RECOVER_UNDO, &undone(false)).await;
        assert_eq!(done.status(), StatusCode::OK);
        let page = html(done).await;
        assert!(page.contains("The recovery is undone."), "{page}");
        assert!(page.contains("Your account is disabled"), "{page}");
    }
}

/// While a recovery can be undone, the account's pages ask whether it was the
/// owner's once the passkey script finds this session has not answered at this
/// stage, with a link to cancel or undo it. While its link works, no passkey can
/// be removed; once it is used, the pages say until when the probation holds its
/// passkey back, and only that passkey can be removed. The passkey list, its
/// removal and the history call it the recovery's passkey, the list with a mark,
/// its enrollment time and its ID; no settings page names it otherwise, the list
/// never renames it, and a report offers to remove no other passkey.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn settings_show_the_recovery() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let recovering = Recovering::new(&database, true).await;
    let browser = recovering.signed_in().await;
    // The passkey sign-in confirmed the session.
    let key = |stage| format!("piquel-recovery:{}:{stage}:confirmed", browser.session_id);
    let asks = |page: &str, stage, refusal| {
        let key = key(stage);
        let banner = format!(r#"<section class="notice stack" data-dismiss="{key}" hidden="">"#);
        let answer = format!(r#"data-dismisses="{key}""#);
        let undo = format!(
            r#"<a href="{RECOVER_UNDO}#recovery={}">{refusal}</a>"#,
            recovering.id
        );
        page.contains(&banner) && page.contains(&answer) && page.contains(&undo)
    };
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(asks(&page, "open", "No, cancel it"), "{page}");
    let locked = "Passkeys can't be removed while the recovery can be cancelled.";
    assert!(page.contains(locked), "{page}");

    let passkey = recovering.enroll("Sneaky name").await;
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(asks(&page, "probation", "No, undo it"), "{page}");
    let recovery = database.recoveries().find(recovering.id).await;
    let settles_at = recovery.expect("lookup").expect("recovery").settles_at;
    let settles_at = time(settles_at.expect("in probation"), "%-d %b %Y");
    assert!(page.contains(&format!("Until {settles_at}")), "{page}");
    let only = format!(
        "Only the recovery's passkey can be removed until the recovery settles on {settles_at}."
    );
    assert!(page.contains(&only), "{page}");
    let mark = r#"<strong>The recovery's passkey</strong><span class="badge">Added by the recovery</span>"#;
    assert!(page.contains(mark), "{page}");
    let added = format!(
        "Added {} · ID {}",
        time(passkey.created_at, MINUTE),
        passkey.id
    );
    assert!(page.contains(&added), "{page}");
    assert!(
        page.contains(r#"aria-label="Rename Existing key""#),
        "{page}"
    );
    assert!(!page.contains("Rename The recovery's passkey"), "{page}");
    assert!(
        page.contains(r#"aria-label="Remove Existing key" disabled="""#),
        "{page}"
    );
    assert!(
        page.contains(r#"aria-label="Remove The recovery's passkey">"#),
        "{page}"
    );

    let opened = |state: SignInState| state.on(settings::HOME).expect("link");
    let removing = opened(SignInState {
        removing: Some(passkey.id),
        ..SignInState::default()
    });
    let renaming = opened(SignInState {
        renaming: Some(passkey.id),
        ..SignInState::default()
    });
    for path in [settings::HOME, &removing, &renaming, settings::HISTORY] {
        let page = html(browser.visit(&replicas.a, path).await).await;
        assert!(!page.contains("Sneaky name"), "{path}: {page}");
    }
    let page = html(browser.visit(&replicas.a, &removing).await).await;
    assert!(page.contains("Remove the recovery's passkey?"), "{page}");
    let page = html(browser.visit(&replicas.a, &renaming).await).await;
    assert!(!page.contains("Save name"), "{page}");
    let older = database.passkeys().list_active(recovering.user_id).await;
    let older = older
        .expect("passkeys")
        .into_iter()
        .find(|key| key.id != passkey.id);
    let older = opened(SignInState {
        removing: Some(older.expect("a passkey from before").id),
        ..SignInState::default()
    });
    let page = html(browser.visit(&replicas.a, &older).await).await;
    assert!(!page.contains("Confirm removal"), "{page}");
    let page = html(browser.visit(&replicas.a, settings::HISTORY).await).await;
    assert!(page.contains("The recovery's passkey renamed"), "{page}");

    // Reporting the older passkey's addition offers no removal: it would be refused.
    let report = HistoryChange::Report {
        event_id: recovering.older.expect("a passkey from before"),
        before: None,
    };
    let reported = browser.post(&replicas, settings::HISTORY, &report).await;
    let page = html(browser.visit(&replicas.a, redirect(&reported)).await).await;
    assert!(page.contains("Your account is secured."), "{page}");
    assert!(!page.contains("Remove passkey"), "{page}");
}

/// A sign-in that goes on to an app first asks whether a recovery of the account
/// that can still be undone was its owner's: its link goes on through the
/// authorization, which it keeps, and another undoes the recovery. A sign-in that
/// goes on to auth's own pages leaves them to ask.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_sign_in_for_an_app_asks_about_a_recovery() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let client = ClientRegistration {
        trusted: true,
        ..registration(ClientKind::Public, "https://client.example")
    };
    register(&database, &client).await.expect("client");
    let authorize = authorize(&client, &[]);
    let sign_in = location(&Browser::signed_out().visit(&replicas.a, &authorize).await);
    let transaction = parameter(&sign_in, "transaction");
    let recovering = Recovering::new(&database, true).await;
    let browser = recovering.signed_in().await;
    let query = LoginQuery {
        transaction: Some(transaction.clone()),
        ..LoginQuery::default()
    };
    let here = query.on(LOGIN).expect("link");
    let asked = browser
        .post(&replicas, &here, &LoginChange::SignedIn {})
        .await;
    assert_eq!(asked.status(), StatusCode::OK);
    let page = html(asked).await;
    let resume = format!("{AUTHORIZE_RESUME}?transaction={transaction}");
    let yes = format!(r#"<a class="button" href="{resume}">Yes, continue</a>"#);
    assert!(page.contains(&yes), "{page}");
    let no = format!(
        r#"<a href="{RECOVER_UNDO}#recovery={}">No, cancel it</a>"#,
        recovering.id
    );
    assert!(page.contains(&no), "{page}");
    let continued = location(&browser.visit(&replicas.a, &resume).await);
    assert_eq!(
        &continued[..Position::AfterPath],
        client.redirect_uris[0].as_str()
    );
    assert!(!parameter(&continued, "code").is_empty(), "{continued}");

    let settled = browser
        .post(&replicas, LOGIN, &LoginChange::SignedIn {})
        .await;
    assert_eq!(settled.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&settled), settings::HOME);
}
