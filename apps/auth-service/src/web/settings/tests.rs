//! The settings pages through the whole service, as a browser uses them.

use crate::{
    AuthConfig,
    routes::page::settings,
    security::BrowserCookie,
    tests::{
        AUTH_ORIGIN, Browser, MAX_RESPONSE_BYTES, OWN_PAGE, Replicas, cookie, html, parameter,
        policy, redirect,
    },
    web::tests::value_after,
};
use axum::http::{StatusCode, header};
use piquel_common::{
    AuthenticationMethod, EventId, Provider, TokenId,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
};
use piquel_crypto::Secret;
use piquel_repository::InsertExternalIdentity;
use piquel_ui::{
    Checkbox, ConnectedAppChange, ConnectedAppsState, DataChange, DeviceChange, EmailChange,
    HistoryChange, HistoryState, Query, SignInChange, SignInState,
};

/// The devices page lists every signed-in browser, and signs one or all of the
/// others out. Only the change itself, never a link, makes the page say so.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn devices_page_signs_other_devices_out() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let other = Browser::sign_in(&database, browser.user_id).await;
    Browser::sign_in(&database, browser.user_id).await;
    let page = html(browser.visit(&replicas.a, settings::SESSIONS).await).await;
    assert!(
        page.contains(r#"<span class="badge">3 active</span>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="badge">This device</span>"#),
        "{page}"
    );
    let forged = format!("{}?done=others_signed_out", settings::SESSIONS);
    let page = html(browser.visit(&replicas.a, &forged).await).await;
    assert!(
        !page.contains("Your other devices were signed out."),
        "{page}"
    );

    let sign_out = DeviceChange::SignOut {
        id: other.session_id,
    };
    let signed_out = browser.post(&replicas, settings::SESSIONS, &sign_out).await;
    assert_eq!(redirect(&signed_out), settings::SESSIONS);
    assert_eq!(
        cookie(&signed_out, BrowserCookie::Notice).0,
        "device_signed_out"
    );
    let page = html(browser.visit(&replicas.a, settings::SESSIONS).await).await;
    assert!(
        page.contains(r#"<span class="badge">2 active</span>"#),
        "{page}"
    );

    let signed_out = browser
        .post(&replicas, settings::SESSIONS, &DeviceChange::SignOutOthers)
        .await;
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&signed_out), settings::SESSIONS);
    let shown = browser
        .following(&signed_out)
        .visit(&replicas.a, settings::SESSIONS)
        .await;
    // The page says it once.
    let (cleared, attributes) = cookie(&shown, BrowserCookie::Notice);
    assert_eq!(cleared, "");
    assert!(attributes.ends_with("Max-Age=0"), "{attributes}");
    let page = html(shown).await;
    assert!(
        page.contains(r#"<span class="badge">1 active</span>"#),
        "{page}"
    );
    assert!(
        page.contains("Your other devices were signed out."),
        "{page}"
    );
}

/// The connected apps page lists an app the account consented to, with what it
/// can see, and removes its access once confirmed. Removing it again says it has
/// none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn connected_apps_are_listed_and_removed() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let client = crate::tests::registration(
        piquel_common::clients::ClientKind::Public,
        "https://client.example",
    );
    crate::tests::register(&database, &client)
        .await
        .expect("register");
    let scopes = ["openid".to_owned(), "email".to_owned()];
    database
        .oidc()
        .save_consent(browser.user_id, &client.id, client.id.as_str(), &scopes)
        .await
        .expect("consent");
    let page = html(browser.visit(&replicas.a, settings::APPS).await).await;
    assert!(page.contains("Your verified email address"), "{page}");
    assert!(page.contains("1 connected"), "{page}");

    let removing = ConnectedAppsState {
        removing: Some(client.id.clone()),
    };
    let link = removing.on(settings::APPS).expect("link");
    let page = html(browser.visit(&replicas.a, &link).await).await;
    assert!(page.contains("will need your approval again"), "{page}");
    let remove = ConnectedAppChange::Remove {
        client_id: client.id.clone(),
    };
    let removed = browser.post(&replicas, settings::APPS, &remove).await;
    assert_eq!(redirect(&removed), settings::APPS);
    assert_eq!(cookie(&removed, BrowserCookie::Notice).0, "app_removed");
    let page = html(browser.visit(&replicas.a, settings::APPS).await).await;
    assert!(page.contains("No apps have access"), "{page}");

    let again = browser.post(&replicas, settings::APPS, &remove).await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    assert!(html(again).await.contains("may already be removed"));
}

/// A change that needs a recent passkey confirmation asks the passkey script for
/// one while the session has none. Posted anyway, it is refused, and its row opens
/// again, with what was typed, to ask once more. A confirmed session makes it at
/// once.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmed_changes_ask_for_a_passkey_first() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let confirmed = Browser::new_account(&database).await;
    let social = Browser::sign_in_with(
        &database,
        confirmed.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let address = format!("{}@example.com", confirmed.user_id);
    let add = EmailChange::Add {
        email: address.clone(),
    };
    let page = html(social.visit(&replicas.a, settings::EMAILS).await).await;
    assert!(page.contains("data-passkey-confirm"), "{page}");
    let refused = social.post(&replicas, settings::EMAILS, &add).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    assert!(
        page.contains("Confirm with your passkey to continue."),
        "{page}"
    );
    assert!(page.contains(&format!(r#"value="{address}""#)), "{page}");
    assert!(page.contains("data-passkey-confirm"), "{page}");

    let page = html(confirmed.visit(&replicas.a, settings::EMAILS).await).await;
    assert!(!page.contains("data-passkey-confirm"), "{page}");
    let added = confirmed.post(&replicas, settings::EMAILS, &add).await;
    assert_eq!(cookie(&added, BrowserCookie::Notice).0, "email_added");
    let page = html(confirmed.visit(&replicas.a, settings::EMAILS).await).await;
    assert!(page.contains(&format!("<span>{address}</span>")), "{page}");
    assert!(page.contains("Waiting for confirmation"), "{page}");

    let id = value_after(&page, r#"name="remove" value=""#)
        .parse()
        .expect("address ID");
    let refused = social
        .post(&replicas, settings::EMAILS, &EmailChange::Remove { id })
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    assert!(page.contains(&format!("Remove {address}?")), "{page}");
    assert!(page.contains("Confirm removal"), "{page}");
}

/// Another verified address can become the primary one, and the former primary
/// address can then be removed.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn addresses_change_their_primary_and_are_removed() {
    let config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    let replicas = Replicas::of(&config).await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let [first, second] =
        ["first", "second"].map(|name| format!("{}-{name}@example.com", browser.user_id));
    let mut ids = Vec::new();
    for address in [&first, &second] {
        let add = EmailChange::Add {
            email: address.clone(),
        };
        browser.post(&replicas, settings::EMAILS, &add).await;
        let emails = database.emails().list(browser.user_id).await.expect("list");
        let id = emails
            .iter()
            .find(|email| email.normalized_email == *address)
            .expect("added")
            .id;
        // The first address confirmed becomes the primary one.
        let token = config.email.verification_key.token(id).expect("token");
        let verified = Browser::signed_out()
            .submit(
                &replicas.b,
                settings::VERIFY,
                &[("token", &token.encoded())],
                OWN_PAGE,
            )
            .await;
        assert_eq!(verified.status(), StatusCode::OK);
        ids.push(id);
    }

    let primary = EmailChange::Primary { id: ids[1] };
    let changed = browser.post(&replicas, settings::EMAILS, &primary).await;
    assert_eq!(cookie(&changed, BrowserCookie::Notice).0, "email_primary");
    let removed = browser
        .post(
            &replicas,
            settings::EMAILS,
            &EmailChange::Remove { id: ids[0] },
        )
        .await;
    assert_eq!(cookie(&removed, BrowserCookie::Notice).0, "email_removed");
    let page = html(browser.visit(&replicas.a, settings::EMAILS).await).await;
    assert!(!page.contains(&first), "{page}");
    assert!(page.contains(&format!("<span>{second}</span>")), "{page}");
    assert!(
        page.contains("Primary: receives security notices"),
        "{page}"
    );
}

/// The handle can change once its cooldown is over. A refusal says why, with the
/// handle typed still in the form, and a change says so.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_handle_changes_once_its_cooldown_is_over() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let taken = Browser::new_account(&database).await;
    let handle = async |browser: &Browser| {
        database
            .users()
            .find_by_id(browser.user_id)
            .await
            .expect("lookup")
            .expect("user")
            .handle
    };
    let (current, taken) = (handle(&browser).await, handle(&taken).await);
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(
        page.contains(&format!("<strong>@{current}</strong>")),
        "{page}"
    );
    assert!(page.contains("You can change it again on"), "{page}");

    database
        .users()
        .age_handle_change(browser.user_id, 31)
        .await
        .expect("age");
    let opened = SignInState {
        changing_handle: Checkbox(true),
        ..SignInState::default()
    };
    let path = opened.on(settings::HOME).expect("query");
    let page = html(browser.visit(&replicas.a, &path).await).await;
    assert!(page.contains(&format!(r#"value="{current}""#)), "{page}");
    let change = |handle: &str| SignInChange::Handle {
        handle: handle.to_owned(),
    };
    let refused = browser
        .post(&replicas, settings::HOME, &change(taken.as_str()))
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let page = html(refused).await;
    assert!(page.contains("This handle is taken."), "{page}");
    assert!(page.contains(&format!(r#"value="{taken}""#)), "{page}");

    let renamed = format!("renamed-{}", &browser.user_id.to_string()[24..]);
    let changed = browser
        .post(&replicas, settings::HOME, &change(&renamed))
        .await;
    assert_eq!(redirect(&changed), settings::HOME);
    assert_eq!(cookie(&changed, BrowserCookie::Notice).0, "handle_changed");
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(
        page.contains(&format!("<strong>@{renamed}</strong>")),
        "{page}"
    );
}

/// A provider linked before it was disabled is still listed, and can be unlinked.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn disabled_providers_can_still_be_unlinked() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    database
        .federation()
        .insert_identity(&InsertExternalIdentity {
            id: TokenId::new(),
            user_id: browser.user_id,
            provider: Provider::GitHub,
            issuer: "https://github.com".into(),
            subject: browser.user_id.to_string(),
            linked_email: None,
        })
        .await
        .expect("identity");
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(
        page.contains("GitHub sign-in is currently unavailable."),
        "{page}"
    );

    let unlink = SignInChange::Unlink {
        provider: Provider::GitHub,
    };
    let unlinked = browser.post(&replicas, settings::HOME, &unlink).await;
    assert_eq!(
        cookie(&unlinked, BrowserCookie::Notice).0,
        "identity_unlinked"
    );
    let page = html(browser.visit(&replicas.a, settings::HOME).await).await;
    assert!(
        page.contains("Social sign-in is not available yet."),
        "{page}"
    );
}

/// Linking a provider starts at the provider, which the page's policy lets its
/// form redirect to, with the cookie binding the flow to the browser. The flow
/// links the browser's session, and comes back to these settings.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn linking_starts_at_the_provider() {
    let config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    let replicas = Replicas::with_github(config).await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let page = browser.visit(&replicas.a, settings::HOME).await;
    let policy = policy(&page);
    assert!(
        policy.ends_with("; form-action 'self' https://github.com"),
        "{policy}"
    );

    let link = SignInChange::Link {
        provider: Provider::GitHub,
    };
    let started = browser.post(&replicas, settings::HOME, &link).await;
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    let to = url::Url::parse(redirect(&started)).expect("provider URL");
    assert_eq!(
        &to[..url::Position::AfterPath],
        "https://github.com/login/oauth/authorize"
    );
    let (value, flags) = cookie(&started, BrowserCookie::Federation);
    assert!(
        flags.starts_with(" Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="),
        "{flags}"
    );

    let state = parameter(&to, "state");
    let flow = database
        .federation()
        .consume_transaction(
            Provider::GitHub,
            Secret::parse(&state).expect("state").digest().as_bytes(),
            Secret::parse(value).expect("cookie").digest().as_bytes(),
        )
        .await
        .expect("the link's transaction");
    assert_eq!(
        (
            flow.link_user_id,
            flow.link_session_id,
            flow.return_to.as_str()
        ),
        (
            Some(browser.user_id),
            Some(browser.session_id),
            settings::HOME
        )
    );
}

/// A history page lists entries with a report button each, older ones a page at a
/// time, but none on the account's creation, which no report applies to. Reporting
/// one opens its confirmation first, and a report goes on to what it left to undo,
/// on the page it was made from. A report the account did not make shows nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn history_reports_need_confirmation_and_cannot_be_forged() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let context = EventContext {
        actor: Actor::User {
            user_id: browser.user_id,
            session_id: Some(browser.session_id),
        },
        origin: RequestOrigin::default(),
        reason: None,
    };
    let created = DomainEvent::AccountCreated {
        method: AuthenticationMethod::Passkey,
        invited: false,
    };
    let mut tx = database.begin().await.expect("transaction");
    tx.record(&context, Some(browser.user_id), created)
        .await
        .expect("record");
    tx.commit().await.expect("commit");
    let created = database
        .events()
        .history_for_user(browser.user_id, 1)
        .await
        .expect("history")[0]
        .id;
    let address = format!("{}@example.com", browser.user_id);
    let add = EmailChange::Add {
        email: address.clone(),
    };
    browser.post(&replicas, settings::EMAILS, &add).await;
    let page = html(browser.visit(&replicas.a, settings::HISTORY).await).await;
    assert!(!page.contains("Secure your account?"), "{page}");
    let marker = r#"name="report" value=""#;
    let added: EventId = value_after(&page, marker).parse().expect("newest entry");
    let link = |state: HistoryState| state.on(settings::HISTORY).expect("link");

    let older = link(HistoryState {
        before: Some(added),
        ..HistoryState::default()
    });
    let page = html(browser.visit(&replicas.a, &older).await).await;
    assert!(!page.contains(&format!("{marker}{added}")), "{page}");
    assert!(page.contains("Newest activity"), "{page}");
    let kept = format!(r#"<input type="hidden" name="before" value="{added}">"#);
    assert!(page.contains(&kept), "{page}");
    let signed_in: EventId = value_after(&page, marker).parse().expect("older entry");
    assert!(page.contains("Account created with a passkey"), "{page}");
    assert!(!page.contains(&format!("{marker}{created}")), "{page}");
    let report = HistoryChange::Report {
        event_id: created,
        before: Some(added),
    };
    let refused = browser.post(&replicas, settings::HISTORY, &report).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(
        page.contains("Only entries from your own sessions can be reported, and not this one."),
        "{page}"
    );

    let forged = link(HistoryState {
        reported: Some(added),
        ..HistoryState::default()
    });
    let page = html(browser.visit(&replicas.a, &forged).await).await;
    assert!(!page.contains("Your account is secured."), "{page}");
    let confirm = link(HistoryState {
        reporting: Some(added),
        ..HistoryState::default()
    });
    let page = html(browser.visit(&replicas.a, &confirm).await).await;
    assert!(page.contains("Secure your account?"), "{page}");

    let report = HistoryChange::Report {
        event_id: added,
        before: None,
    };
    let reported = browser.post(&replicas, settings::HISTORY, &report).await;
    assert_eq!(redirect(&reported), forged);
    let page = html(browser.visit(&replicas.a, &forged).await).await;
    assert!(
        page.contains("<strong>Your account is secured.</strong>"),
        "{page}"
    );
    // Undoing the address removes it on its own page.
    assert!(
        page.contains(r#"<form method="post" action="/settings/emails""#),
        "{page}"
    );
    assert!(page.contains(&format!("Remove {address}")), "{page}");

    let report = HistoryChange::Report {
        event_id: signed_in,
        before: Some(added),
    };
    let reported = browser.post(&replicas, settings::HISTORY, &report).await;
    let shown = link(HistoryState {
        before: Some(added),
        reporting: None,
        reported: Some(signed_in),
    });
    assert_eq!(redirect(&reported), shown);
}

/// The verification page never verifies on its own: its form does, signed out.
/// Neither another account nor a token that does not match can, and a refused
/// confirmation still leads to the addresses.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn verification_links_are_confirmed_by_their_form() {
    let config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    let replicas = Replicas::of(&config).await;
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let address = format!("{}@example.com", owner.user_id);
    let add = EmailChange::Add {
        email: address.clone(),
    };
    owner.post(&replicas, settings::EMAILS, &add).await;
    let page = html(owner.visit(&replicas.a, settings::EMAILS).await).await;
    let id = value_after(&page, r#"name="remove" value=""#)
        .parse()
        .expect("address ID");
    let token = config
        .email
        .verification_key
        .token(id)
        .expect("token")
        .encoded();

    let browser = Browser::signed_out();
    let page = browser.visit(&replicas.a, settings::VERIFY).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = html(page).await;
    assert!(page.contains("data-fragment-form"), "{page}");
    let refused = browser
        .submit(
            &replicas.b,
            settings::VERIFY,
            &[("token", "spent")],
            OWN_PAGE,
        )
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(page.contains(r#"role="alert""#), "{page}");
    assert!(page.contains("Manage your addresses"), "{page}");

    let other = Browser::new_account(&database).await;
    let refused = other
        .submit(
            &replicas.b,
            settings::VERIFY,
            &[("token", &token)],
            OWN_PAGE,
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let page = html(refused).await;
    assert!(
        page.contains("other than the one you are signed in to"),
        "{page}"
    );

    let verified = browser
        .submit(
            &replicas.b,
            settings::VERIFY,
            &[("token", &token)],
            OWN_PAGE,
        )
        .await;
    assert_eq!(verified.status(), StatusCode::OK);
    let page = html(verified).await;
    assert!(page.contains(&format!("{address} is verified")), "{page}");
}

/// The data page downloads the account's records once the session confirmed with a
/// passkey, and deletes the account once its handle is typed: every browser is
/// signed out, and the answer says when the account is purged.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn data_page_downloads_the_data_and_deletes_the_account() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let handle = database
        .users()
        .find_by_id(browser.user_id)
        .await
        .expect("lookup")
        .expect("account")
        .handle
        .to_string();
    let social =
        Browser::sign_in_with(&database, browser.user_id, AuthenticationMethod::Federation).await;
    let page = html(social.visit(&replicas.a, settings::DATA).await).await;
    assert!(page.contains("data-passkey-confirm"), "{page}");
    let refused = social
        .post(&replicas, settings::DATA, &DataChange::Export)
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    let download = browser
        .post(&replicas, settings::DATA, &DataChange::Export)
        .await;
    assert_eq!(download.status(), StatusCode::OK);
    let headers = download.headers();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store, no-transform");
    let disposition = headers[header::CONTENT_DISPOSITION]
        .to_str()
        .expect("disposition");
    assert!(
        disposition.starts_with(&format!("attachment; filename=\"piquel-account-{handle}-")),
        "{disposition}"
    );
    let body = axum::body::to_bytes(download.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("body");
    let export: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(export["format"], "piquel.account-export");

    let opened = format!("{}?delete=true", settings::DATA);
    let page = html(browser.visit(&replicas.a, &opened).await).await;
    assert!(
        page.contains(&format!("Type your handle, {handle}, to confirm")),
        "{page}"
    );
    let mismatch = DataChange::Delete {
        handle: "someone-else".into(),
    };
    let refused = browser.post(&replicas, settings::DATA, &mismatch).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(page.contains("Type your handle exactly as shown"), "{page}");
    assert!(
        page.contains("Type your handle, "),
        "the row stays open: {page}"
    );

    let delete = DataChange::Delete {
        handle: handle.clone(),
    };
    let deleted = browser.post(&replicas, settings::DATA, &delete).await;
    assert_eq!(deleted.status(), StatusCode::OK);
    let (cleared, attributes) = cookie(&deleted, BrowserCookie::Session);
    assert_eq!(cleared, "");
    assert!(attributes.ends_with("Max-Age=0"), "{attributes}");
    let page = html(deleted).await;
    assert!(
        page.contains("Your account is scheduled for deletion"),
        "{page}"
    );
    assert!(page.contains("Restore my account"), "{page}");
    let page = html(social.visit(&replicas.a, settings::DATA).await).await;
    assert!(!page.contains("Download your data"), "signed out: {page}");
}
