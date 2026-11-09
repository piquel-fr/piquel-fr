//! The recovery pages, and what the account's pages and its sign-ins ask of a
//! recovery, through the whole service, as a browser uses them.

use crate::{
    AdminService,
    deletion::Deletions,
    recovery::PROBATION,
    routes::{
        self,
        oidc::AUTHORIZE_RESUME,
        page::{LOGIN, RECOVER, RECOVER_UNDO, settings},
    },
    security::{BrowserCookie, RequestContext},
    tests::{
        Browser, Replicas, captures, ceremonies, cookie, html, location, operator, parameter,
        policy, recovery_links, recovery_reason, recovery_token, redirect, register, registration,
        sends, unusable_passkey,
    },
    web::tests::authorize,
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
    Checkbox, HistoryChange, LoginChange, LoginQuery, Query, RecoverChange, SignInState, UndoChange,
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
        let link = AdminService::new(database.clone(), true)
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
            handle: account.expect("lookup").expect("account").handle.into(),
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

    /// A signed-out browser holding the offer to restore the account, which
    /// support schedules for deletion, that a sign-in with the passkey from before
    /// the recovery made.
    async fn restore_offer(&self) -> Browser {
        AdminService::new(self.database.clone(), true)
            .schedule_deletion(&operator(), self.user_id, recovery_reason())
            .await
            .expect("scheduled");
        let passkeys = self.database.passkeys().list_active(self.user_id).await;
        let older = passkeys
            .expect("passkeys")
            .into_iter()
            .find(|passkey| passkey.friendly_name == "Existing key")
            .expect("older passkey");
        let mut tx = self.database.begin().await.expect("transaction");
        tx.users()
            .find_by_id_for_update(self.user_id)
            .await
            .expect("lock");
        let offered = Deletions::offer_restore(tx, self.user_id, older.id)
            .await
            .expect("offer");
        let mut response = axum::http::Response::new(());
        offered.set_on(&mut response).expect("cookie");
        let response = axum::response::Response::from_parts(
            response.into_parts().0,
            axum::body::Body::empty(),
        );
        let (offer, _) = cookie(&response, BrowserCookie::Restore);
        Browser::signed_out().with_cookie(BrowserCookie::Restore, offer)
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
/// probation holds back. The token rides only in the passkey ceremony, so the
/// form never posts it again. Once the ceremony added the passkey, the browser
/// it signed in goes on to the settings.
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
    assert!(page.contains("This link is incomplete"), "{page}");

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
    assert!(!page.contains("This link is incomplete"), "{page}");

    let opened = browser
        .post(&replicas, RECOVER, &open(&recovering.token))
        .await;
    assert_eq!(opened.status(), StatusCode::OK);
    let page = html(opened).await;
    let heading = format!("Add a passkey to @{} (Browser test)", recovering.handle);
    assert!(page.contains(&heading), "{page}");
    assert_eq!(ceremonies(&page, routes::recovery::START), 1, "{page}");
    assert!(sends(&page, "token", &recovering.token), "{page}");
    assert!(!page.contains(r#"name="token""#), "{page}");
    assert!(captures(&page, RECOVER), "{page}");
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
/// none. Once the browser undid it, a browser the undo signed in goes on to
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
    let undoes = |page: &str| sends(page, "recovery_id", &recovering.id.to_string());
    let outcome = r#"<input type="hidden" name="action" value="undone"><input type="hidden" name="signed_in" value="false">"#;
    let named = open(Some(recovering.id));
    let page = html(browser.post(&replicas, RECOVER_UNDO, &named).await).await;
    assert!(page.contains("Cancel this recovery?"), "{page}");
    assert!(page.contains("a recovery of your account"), "{page}");
    assert!(
        page.contains("If the link is used before you cancel, cancelling takes back"),
        "{page}"
    );
    assert!(undoes(&page), "{page}");
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
    assert!(undoes(&page), "{page}");

    for recovery in [Some(RecoveryId::new()), None] {
        let nothing = browser.post(&replicas, RECOVER_UNDO, &open(recovery)).await;
        assert_eq!(nothing.status(), StatusCode::NOT_FOUND, "{recovery:?}");
        assert!(html(nothing).await.contains("nothing to undo"));
    }
    let unaided = Recovering::new(&database, false).await;
    let unaided = open(Some(unaided.id));
    let page = html(browser.post(&replicas, RECOVER_UNDO, &unaided).await).await;
    assert!(page.contains("only Piquel support can undo it"), "{page}");
    assert_eq!(ceremonies(&page, routes::recovery::UNDO_START), 0, "{page}");

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
/// owner's once the browser finds this session has not answered at this
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
        let banner = r#"<section class="notice warning stack" "#;
        let answer = ">Yes, it was me</button>";
        let undo = format!(
            r#"<a class="button danger small" href="{RECOVER_UNDO}#recovery={}">{refusal}</a>"#,
            recovering.id
        );
        page.contains(banner)
            && captures(page, &key)
            && page.contains(answer)
            && page.contains(&undo)
    };
    let page = html(browser.visit(&replicas.a, settings::SIGN_IN).await).await;
    assert!(asks(&page, "open", "No, cancel it"), "{page}");
    let locked = "Passkeys can't be removed while the recovery can be cancelled.";
    assert!(page.contains(locked), "{page}");

    let passkey = recovering.enroll("Sneaky name").await;
    let page = html(browser.visit(&replicas.a, settings::SIGN_IN).await).await;
    assert!(asks(&page, "probation", "No, undo it"), "{page}");
    let recovery = database.recoveries().find(recovering.id).await;
    let settles_at = recovery.expect("lookup").expect("recovery").settles_at;
    let settles_at = time(settles_at.expect("in probation"), "%-d %b %Y");
    assert!(page.contains(&format!("Until {settles_at}")), "{page}");
    let only = format!(
        "Only the recovery's passkey can be removed until the recovery settles on {settles_at}."
    );
    assert!(page.contains(&only), "{page}");
    let mark = r#"<strong>The recovery's passkey</strong> <span class="badge warning">Added by the recovery</span>"#;
    assert!(page.contains(mark), "{page}");
    let added = format!(
        "added {} · ID {}",
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

    let opened = |state: SignInState| state.on(settings::SIGN_IN).expect("link");
    let removing = opened(SignInState {
        removing: Some(passkey.id),
        ..SignInState::default()
    });
    let renaming = opened(SignInState {
        renaming: Some(passkey.id),
        ..SignInState::default()
    });
    for path in [settings::SIGN_IN, &removing, &renaming, settings::HISTORY] {
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

/// A recovering account and a trusted app its sign-ins go on to.
struct ForAnApp {
    /// The service.
    replicas: Replicas,
    /// The app.
    client: ClientRegistration,
    /// Its authorization request.
    authorize: String,
    /// The account.
    recovering: Recovering,
}

impl ForAnApp {
    /// An account recovering with a passkey from before, and the app.
    async fn new() -> Self {
        let replicas = Replicas::new().await;
        let database = Replicas::database().await;
        let client = ClientRegistration {
            trusted: true,
            ..registration(ClientKind::Public, "https://client.example")
        };
        register(&database, &client).await.expect("client");
        let authorize = authorize(&client, &[]);
        let recovering = Recovering::new(&database, true).await;
        Self {
            replicas,
            client,
            authorize,
            recovering,
        }
    }

    /// Starts an authorization in a signed-out browser, and returns its token.
    async fn start(&self) -> String {
        let browser = Browser::signed_out();
        let sign_in = location(&browser.visit(&self.replicas.a, &self.authorize).await);
        parameter(&sign_in, "transaction")
    }

    /// Asserts that `response` sends the browser on to the app with a code.
    fn reaches_the_app(&self, response: &axum::response::Response) {
        let continued = location(response);
        let app = self.client.redirect_uris[0].as_str();
        assert_eq!(&continued[..Position::AfterPath], app);
        assert!(!parameter(&continued, "code").is_empty(), "{continued}");
    }

    /// Where `response` sends the browser, from the path on.
    fn to(response: &axum::response::Response) -> String {
        location(response)[Position::BeforePath..].to_owned()
    }

    /// The sign-in page continuing `transaction`, asking the question if `asks`.
    fn sign_in(transaction: &str, asks: bool) -> String {
        let query = LoginQuery {
            transaction: Some(transaction.to_owned()),
            recovery: Checkbox(asks),
            ..LoginQuery::default()
        };
        query.on(LOGIN).expect("link")
    }

    /// The path resuming `transaction`.
    fn resume(transaction: &str) -> String {
        format!("{AUTHORIZE_RESUME}?transaction={transaction}")
    }
}

/// A sign-in that goes on to an app first asks whether a recovery of the account
/// that can still be undone was its owner's, whichever way it signed in: on the
/// sign-in page, or by resuming the authorization, as a provider's sign-in does.
/// Only the question's form goes on, keeping the authorization, so no link skips
/// it, and an answer about another recovery answers nothing; its other answer
/// undoes the recovery. A browser that signed in before the authorization
/// started is not asked, and a sign-in that goes on to auth's own pages leaves
/// them to ask.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_sign_in_for_an_app_asks_about_a_recovery() {
    let app = ForAnApp::new().await;
    let replicas = &app.replicas;
    let recovering = &app.recovering;

    // Signing in on the sign-in page.
    let transaction = app.start().await;
    let question = ForAnApp::sign_in(&transaction, true);
    let browser = recovering.signed_in().await;
    let here = ForAnApp::sign_in(&transaction, false);
    let signed_in = browser
        .post(replicas, &here, &LoginChange::SignedIn {})
        .await;
    assert_eq!(ForAnApp::to(&signed_in), question);
    // Resuming it instead, as a link could, asks again.
    let resumed = browser
        .visit(&replicas.a, &ForAnApp::resume(&transaction))
        .await;
    assert_eq!(ForAnApp::to(&resumed), question);
    let asked = browser.visit(&replicas.a, &question).await;
    assert_eq!(asked.status(), StatusCode::OK);
    // Its form may go on to the app.
    let form_action = policy(&asked)
        .split(';')
        .find(|directive| directive.trim().starts_with("form-action"))
        .expect("form-action");
    assert!(
        form_action.contains("https://client.example"),
        "{form_action}"
    );
    let page = html(asked).await;
    let yes = format!(
        r#"<input type="hidden" name="action" value="recovery_recognized"><input type="hidden" name="recovery" value="{}">"#,
        recovering.id
    );
    assert!(page.contains(&yes), "{page}");
    let no = format!(
        r#"<a class="button secondary full" href="{RECOVER_UNDO}#recovery={}">No, cancel it</a>"#,
        recovering.id
    );
    assert!(page.contains(&no), "{page}");
    // An answer about another recovery, as from a tab another account left open,
    // answers nothing.
    let stale = LoginChange::RecoveryRecognized {
        recovery: RecoveryId::new(),
    };
    let stale = browser.post(replicas, &question, &stale).await;
    assert_eq!(ForAnApp::to(&stale), question);
    let answer = LoginChange::RecoveryRecognized {
        recovery: recovering.id,
    };
    app.reaches_the_app(&browser.post(replicas, &question, &answer).await);

    // Signing in some other way resumes the authorization, which asks.
    let transaction = app.start().await;
    let browser = recovering.signed_in().await;
    let resumed = browser
        .visit(&replicas.a, &ForAnApp::resume(&transaction))
        .await;
    assert_eq!(
        ForAnApp::to(&resumed),
        ForAnApp::sign_in(&transaction, true)
    );

    // A browser already signed in goes on without asking.
    app.reaches_the_app(&browser.visit(&replicas.a, &app.authorize).await);

    let settled = browser
        .post(replicas, LOGIN, &LoginChange::SignedIn {})
        .await;
    assert_eq!(settled.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&settled), settings::HOME);
}

/// Restoring an account support scheduled for deletion during its recovery's
/// probation, which the deletion leaves, with a passkey from before the
/// recovery, for an app, resumes the authorization, which asks about the
/// recovery too.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn restoring_for_an_app_asks_about_a_recovery() {
    let app = ForAnApp::new().await;
    let transaction = app.start().await;
    app.recovering.enroll("Recovered passkey").await;
    let restoring = app.recovering.restore_offer().await;
    let here = ForAnApp::sign_in(&transaction, false);
    let restored = restoring
        .post(&app.replicas, &here, &LoginChange::Restore {})
        .await;
    let resume = ForAnApp::resume(&transaction);
    assert_eq!(redirect(&restored), resume);
    let (session, _) = cookie(&restored, BrowserCookie::Session);
    let browser = Browser::signed_out().with_cookie(BrowserCookie::Session, session);
    let resumed = browser.visit(&app.replicas.a, &resume).await;
    assert_eq!(
        ForAnApp::to(&resumed),
        ForAnApp::sign_in(&transaction, true)
    );
}
