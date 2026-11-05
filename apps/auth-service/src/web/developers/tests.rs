//! The developer console through the whole service, as a browser uses it.

use crate::{
    routes::page::developers::{self, APP, APP_SECRETS, APP_SETTINGS, HOME, NEW},
    security::BrowserCookie,
    routes,
    tests::{Browser, Replicas, captures, ceremonies, cookie, html, policy, redirect},
    web::tests::value_after,
};
use axum::{
    http::{StatusCode, header},
    response::Response,
};
use chrono::{Duration, Utc};
use piquel_common::{AuthenticationMethod, ClientId, clients::ClientKind, protocol::oauth::Scope};
use piquel_ui::{
    AppChange, AppSettingsState, Checkbox, ClientDraft, Grace, Lines, MISSING, NewAppChange, Query,
    SecretsChange,
};
use topcoat::router::content::Form;

/// The settings a developer types into the form for an app calling back to
/// `callback`.
fn draft(callback: &str) -> ClientDraft {
    ClientDraft {
        display_name: "Console test".into(),
        redirect_uris: Lines::from(callback),
        scopes: [Scope::OpenId, Scope::Profile].into_iter().collect(),
        ..ClientDraft::default()
    }
}

/// Registering an app of `kind` calling back to `callback`, as the new-app form
/// posts it.
fn registration(kind: ClientKind, callback: &str) -> NewAppChange {
    NewAppChange::Register {
        kind: Some(kind),
        draft: draft(callback),
    }
}

/// The client secret `page` shows, and that it shows it once.
fn secret(page: &str) -> &str {
    let secret = value_after(page, r#"<code id="client-secret">"#);
    assert!(secret.starts_with("pqcs_"), "{page}");
    assert_eq!(page.matches(secret).count(), 1, "{page}");
    secret
}

/// That `response` is the console's refusal of an app it does not show, below the
/// account's bar, whose navigation marks the section the page is in.
async fn assert_missing(response: Response) {
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let page = html(response).await;
    assert!(page.contains(MISSING), "{page}");
    let section = format!(r#"<a href="{HOME}" title="Your apps" aria-current="page">"#);
    assert!(page.contains(&section), "{page}");
}

/// That `response`, which shows a secret, is the page itself, stored nowhere: no
/// redirect, no cookie, and no copy in any cache.
fn assert_unstored(response: &Response) {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "no-store, no-transform"
    );
    assert!(response.headers().get(header::LOCATION).is_none());
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

/// A browser's form bodies decode as the console's changes: a textarea's lines,
/// one field per checkbox, absent when unchecked, a text input's value, the kind's
/// radio and the grace's select.
#[test]
fn browser_forms_decode() {
    let Form(save) = Form::<AppChange>::from_bytes(
        b"action=save&display_name=Notes&redirect_uris=https%3A%2F%2Fa.example%2Fcb%0D%0A%0D%0A+https%3A%2F%2Fb.example%2Fcb+&post_logout_uris=&openid=on&allow_refresh=on&backchannel_logout_uri=https%3A%2F%2Fa.example%2Flogout",
    )
    .expect("save");
    let AppChange::Save { draft } = save else {
        panic!("{save:?}");
    };
    assert_eq!(
        draft,
        ClientDraft {
            display_name: "Notes".into(),
            redirect_uris: ["https://a.example/cb", "https://b.example/cb"]
                .map(str::to_owned)
                .into_iter()
                .collect(),
            scopes: [Scope::OpenId].into_iter().collect(),
            allow_refresh: Checkbox(true),
            backchannel_logout_uri: "https://a.example/logout".into(),
            ..ClientDraft::default()
        }
    );
    let Form(NewAppChange::Register { kind, .. }) = Form::<NewAppChange>::from_bytes(
        b"action=register&display_name=Notes&kind=public&redirect_uris=https%3A%2F%2Fa.example%2Fcb&post_logout_uris=",
    )
    .expect("registration");
    assert_eq!(kind, Some(ClientKind::Public));
    let Form(SecretsChange::Rotate { grace }) =
        Form::<SecretsChange>::from_bytes(b"action=rotate&grace=7d").expect("rotation");
    assert_eq!(grace, Some(Grace::Week));
}

/// A confidential app's secret shows once, in the answer registering it, which
/// nothing stores and which asks the passkey script to put back the form's address;
/// neither its overview nor the apps show it again. A rotation shows the new one the
/// same way, and lists when the earlier one stops working: once the grace chosen
/// ends.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn secrets_show_once_in_the_answer_that_makes_them() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let register = registration(ClientKind::Confidential, "https://console.example/callback");
    let registered = browser.post(&replicas, NEW, &register).await;
    assert_unstored(&registered);
    assert!(
        policy(&registered).ends_with("; form-action 'self'"),
        "{}",
        policy(&registered)
    );
    let page = html(registered).await;
    let first = secret(&page).to_owned();
    assert!(captures(&page, "/developers/new"), "{page}");
    let id: ClientId = value_after(&page, r#"href="/developers/clients/"#)
        .parse()
        .expect("app ID");
    let overview = developers::of(APP, &id);
    let saved = format!(r#"<a class="button" href="{overview}">I saved it</a>"#);
    assert!(page.contains(&saved), "{page}");

    let secrets = developers::of(APP_SECRETS, &id);
    for path in [overview.as_str(), HOME, &secrets] {
        let page = html(browser.visit(&replicas.a, path).await).await;
        assert!(page.contains("Console test"), "{page}");
        assert!(!page.contains(&first), "{page}");
    }

    let rotate = SecretsChange::Rotate {
        grace: Some(Grace::Hour),
    };
    let rotated = browser.post(&replicas, &secrets, &rotate).await;
    assert_unstored(&rotated);
    let page = html(rotated).await;
    let second = secret(&page);
    assert_ne!(second, first);
    assert!(captures(&page, &secrets), "{page}");
    assert!(page.contains("stops working "), "{page}");
    assert!(page.contains("works until you rotate it"), "{page}");
    let secrets = database.oidc().client_secrets(&id).await.expect("secrets");
    let [earlier, newest] = secrets.as_slice() else {
        panic!("{secrets:?}");
    };
    assert!(newest.expires_at.is_none(), "{secrets:?}");
    let expires_at = earlier.expires_at.expect("the earlier secret expires");
    let late = (expires_at - (Utc::now() + Duration::hours(1))).abs();
    assert!(late < Duration::minutes(1), "{expires_at}");
}

/// A public app goes on to its overview, which says it was registered, and has no
/// secrets. Deleting it, once its confirmation is open, goes back to the apps,
/// which say so, and its pages are missing from then on.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn public_apps_are_registered_then_deleted() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let register = registration(ClientKind::Public, "https://console.example/callback");
    let registered = browser.post(&replicas, NEW, &register).await;
    assert_eq!(registered.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        cookie(&registered, BrowserCookie::Notice).0,
        "client_registered"
    );
    let overview = redirect(&registered).to_owned();
    let id: ClientId = overview
        .strip_prefix("/developers/clients/")
        .expect("an app's overview")
        .parse()
        .expect("app ID");
    let page = html(
        browser
            .following(&registered)
            .visit(&replicas.a, &overview)
            .await,
    )
    .await;
    assert!(page.contains("The app was registered."), "{page}");
    assert!(
        page.contains("<code id=\"client-auth\">none</code>"),
        "{page}"
    );
    assert!(!page.contains(">Secrets</a>"), "{page}");
    let secrets = developers::of(APP_SECRETS, &id);
    assert_missing(browser.visit(&replicas.a, &secrets).await).await;

    let settings = developers::of(APP_SETTINGS, &id);
    let deleting = AppSettingsState {
        deleting: Checkbox(true),
        draft: None,
    };
    let page = html(
        browser
            .visit(&replicas.a, &deleting.on(&settings).expect("link"))
            .await,
    )
    .await;
    assert!(page.contains("Delete “Console test”?"), "{page}");
    let deleted = browser
        .post(&replicas, &settings, &AppChange::Delete {})
        .await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&deleted), HOME);
    assert_eq!(cookie(&deleted, BrowserCookie::Notice).0, "client_deleted");
    let page = html(browser.following(&deleted).visit(&replicas.a, HOME).await).await;
    assert!(page.contains("The app was deleted."), "{page}");
    assert!(page.contains("You have no apps yet."), "{page}");
    assert_missing(browser.visit(&replicas.a, &overview).await).await;
}

/// Every page of another account's app, or of an app no account has, is missing,
/// read or posted to, and nothing changes the app.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn other_accounts_apps_are_missing() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let theirs = owner
        .register_app(
            &database,
            ClientKind::Confidential,
            "https://theirs.example",
        )
        .await;
    let browser = Browser::new_account(&database).await;
    let unknown = "c_unknown".parse().expect("client ID");
    for id in [&theirs, &unknown] {
        for route in [APP, APP_SETTINGS, APP_SECRETS] {
            let path = developers::of(route, id);
            assert_missing(browser.visit(&replicas.a, &path).await).await;
        }
        for route in [APP, APP_SETTINGS] {
            let path = developers::of(route, id);
            assert_missing(browser.post(&replicas, &path, &AppChange::Delete {}).await).await;
        }
        let rotate = SecretsChange::Rotate { grace: None };
        let path = developers::of(APP_SECRETS, id);
        assert_missing(browser.post(&replicas, &path, &rotate).await).await;
    }
    let client = database
        .oidc()
        .find_client(theirs.as_str())
        .await
        .expect("lookup")
        .expect("their app");
    assert!(client.deleted_at.is_none());
    let secrets = database
        .oidc()
        .client_secrets(&theirs)
        .await
        .expect("secrets");
    assert_eq!(secrets.len(), 1);
}

/// Every change to an app needs a passkey: a session without a recent
/// confirmation sees every form ask for one. Its save is refused with what was
/// typed shown again, and so are disabling and deleting it, whose refusal opens its
/// confirmation again, and the app stays as it was. A confirmed session saves.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_change_needs_a_passkey() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let confirmed = Browser::new_account(&database).await;
    let id = confirmed
        .register_app(&database, ClientKind::Confidential, "https://saved.example")
        .await;
    let social = Browser::sign_in_with(
        &database,
        confirmed.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let settings = developers::of(APP_SETTINGS, &id);
    let page = html(social.visit(&replicas.a, &settings).await).await;
    assert_eq!(ceremonies(&page, routes::passkey::CONFIRM_START), 2, "{page}");
    let app = async || {
        database
            .oidc()
            .find_client(id.as_str())
            .await
            .expect("lookup")
            .expect("the app")
    };
    let before = app().await;

    // As the form shows the app, renamed.
    let renamed = ClientDraft {
        display_name: "Renamed".into(),
        redirect_uris: Lines::from("https://saved.example/callback"),
        scopes: [Scope::OpenId, Scope::OfflineAccess].into_iter().collect(),
        allow_refresh: Checkbox(true),
        ..ClientDraft::default()
    };
    let save = AppChange::Save { draft: renamed };
    let refused = social.post(&replicas, &settings, &save).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    assert!(
        page.contains("Confirm with your passkey to continue."),
        "{page}"
    );
    assert!(page.contains(r#"value="Renamed""#), "{page}");
    assert!(ceremonies(&page, routes::passkey::CONFIRM_START) > 0, "{page}");

    let refused = social
        .post(&replicas, &settings, &AppChange::Disable {})
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let refused = social
        .post(&replicas, &settings, &AppChange::Delete {})
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = html(refused).await;
    let confirmation = page
        .find(&format!("Delete “{}”?", before.display_name))
        .expect("confirmation");
    assert!(
        ceremonies(&page[confirmation..], routes::passkey::CONFIRM_START) > 0,
        "{page}"
    );
    let after = app().await;
    assert_eq!(after.display_name, before.display_name);
    assert!(after.enabled && after.deleted_at.is_none());

    let page = html(confirmed.visit(&replicas.a, &settings).await).await;
    assert_eq!(ceremonies(&page, routes::passkey::CONFIRM_START), 0, "{page}");
    let saved = confirmed.post(&replicas, &settings, &save).await;
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&saved), settings);
    assert_eq!(cookie(&saved, BrowserCookie::Notice).0, "client_saved");
    assert_eq!(app().await.display_name, "Renamed");
}

/// A setting the service refuses is said beside its input, which shows what was
/// typed, and nothing is registered.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn refused_settings_are_said_beside_their_input() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let register = registration(ClientKind::Confidential, "http://console.example/callback");
    let refused = browser.post(&replicas, NEW, &register).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(
        page.contains(
            r#"aria-invalid="true" aria-describedby="redirect_uris-help redirect_uris-error""#
        ),
        "{page}"
    );
    let error = value_after(&page, r#"<p class="field-error" id="redirect_uris-error">"#);
    assert!(error.contains("must use https"), "{error}");
    assert!(
        page.contains(">http://console.example/callback</textarea>"),
        "{page}"
    );
    let page = html(browser.visit(&replicas.a, HOME).await).await;
    assert!(page.contains("You have no apps yet."), "{page}");
}

/// A back-channel logout URI is set when an app is registered, which its overview
/// and settings show, then changed and removed from its settings. One the service
/// refuses is said beside its input, which shows what was typed, and the stored
/// one stays.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn backchannel_logout_uris_are_set_changed_and_removed() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let callback = "https://console.example/callback";
    let with = |uri: &str| ClientDraft {
        backchannel_logout_uri: uri.into(),
        ..draft(callback)
    };
    let told = "https://console.example/auth/backchannel-logout";
    let register = NewAppChange::Register {
        kind: Some(ClientKind::Public),
        draft: with(told),
    };
    let registered = browser.post(&replicas, NEW, &register).await;
    assert_eq!(registered.status(), StatusCode::SEE_OTHER);
    let overview = redirect(&registered).to_owned();
    let page = html(browser.visit(&replicas.a, &overview).await).await;
    let fact = format!(r#"<code id="backchannel-logout">{told}</code>"#);
    assert!(page.contains(&fact), "{page}");
    let id: ClientId = overview
        .strip_prefix("/developers/clients/")
        .expect("an app's overview")
        .parse()
        .expect("app ID");
    let settings = developers::of(APP_SETTINGS, &id);
    let page = html(browser.visit(&replicas.a, &settings).await).await;
    assert!(page.contains(&format!(r#"value="{told}""#)), "{page}");
    let stored = async || {
        database
            .oidc()
            .find_client(id.as_str())
            .await
            .expect("lookup")
            .expect("the app")
            .backchannel_logout_uri
    };

    let insecure = "http://console.example/logout";
    let save = AppChange::Save {
        draft: with(insecure),
    };
    let refused = browser.post(&replicas, &settings, &save).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    let error = value_after(
        &page,
        r#"<p class="field-error" id="backchannel_logout_uri-error">"#,
    );
    assert!(error.contains("must use https"), "{error}");
    assert!(page.contains(&format!(r#"value="{insecure}""#)), "{page}");
    assert_eq!(stored().await.as_deref(), Some(told));

    let moved = "https://console.example/logout";
    let save = AppChange::Save { draft: with(moved) };
    let saved = browser.post(&replicas, &settings, &save).await;
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(stored().await.as_deref(), Some(moved));
    // A blank input is no URI.
    let save = AppChange::Save { draft: with(" ") };
    let saved = browser.post(&replicas, &settings, &save).await;
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(stored().await, None);
}

/// The crumb leads through the console to an app, named as its owner named it,
/// and on to its settings, named in lowercase like the console: an app's page
/// reads "developers / Console test", its settings "developers / Console test /
/// settings", the app linking its page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_crumb_leads_through_the_app() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let registered = browser
        .post(
            &replicas,
            NEW,
            &registration(ClientKind::Public, "https://console.example/callback"),
        )
        .await;
    let overview = redirect(&registered).to_owned();
    let page = html(browser.visit(&replicas.a, &overview).await).await;
    assert!(
        page.contains(r#"<a href="/developers">developers</a>"#),
        "{page}"
    );
    assert!(page.contains("<b>Console test</b>"), "{page}");
    let id: ClientId = overview
        .strip_prefix("/developers/clients/")
        .expect("an app's overview")
        .parse()
        .expect("app ID");
    let settings = developers::of(APP_SETTINGS, &id);
    let page = html(browser.visit(&replicas.a, &settings).await).await;
    assert!(
        page.contains(&format!(r#"<a href="{overview}">Console test</a>"#)),
        "{page}"
    );
    assert!(page.contains("<b>settings</b>"), "{page}");
}
