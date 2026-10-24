//! The settings pages through the whole service, as a browser uses them.

use crate::{
    AuthConfig,
    config::ProviderConfig,
    routes::page::{ROOT, settings},
    security::BrowserCookie,
    tests::{AUTH_ORIGIN, Browser, Replicas, parameter, redirect},
    web::tests::{OWN_PAGE, html, policy},
};
use axum::{
    http::{StatusCode, header},
    response::Response,
};
use piquel_common::{AuthenticationMethod, EventId, Provider, TokenId};
use piquel_crypto::Secret;
use piquel_repository::InsertExternalIdentity;
use piquel_ui::{DeviceChange, EmailChange, HistoryChange, HistoryState, Query, SignInChange};
use serde::Serialize;

/// The settings tabs.
const PAGES: [&str; 4] = [
    settings::HOME,
    settings::EMAILS,
    settings::SESSIONS,
    settings::HISTORY,
];

impl Browser {
    /// This browser as it follows `response`'s redirect, holding the notice it set.
    fn following(&self, response: &Response) -> Self {
        let (notice, _) = cookie(response, BrowserCookie::Notice);
        Self {
            user_id: self.user_id,
            session_id: self.session_id,
            cookie: format!(
                "{}; {}={notice}",
                self.cookie,
                BrowserCookie::Notice.as_str()
            ),
        }
    }

    /// Posts `change` to the settings page at `path`, as the page's form sends it.
    async fn post(&self, replicas: &Replicas, path: &str, change: &impl Serialize) -> Response {
        let encoded = serde_urlencoded::to_string(change).expect("change");
        let fields: Vec<(String, String)> = serde_urlencoded::from_str(&encoded).expect("fields");
        let fields: Vec<_> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        self.submit(&replicas.b, path, &fields, OWN_PAGE).await
    }
}

/// The value `response` sets the cookie `name` to, and the cookie's attributes.
fn cookie(response: &Response, name: BrowserCookie) -> (&str, &str) {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .find_map(|cookie| cookie.strip_prefix(name.as_str())?.strip_prefix('='))
        .and_then(|cookie| cookie.split_once(';'))
        .unwrap_or_else(|| panic!("{name} is set"))
}

/// The ID `page` writes right after `marker`, such as the one a form sends.
fn id_after<'a>(page: &'a str, marker: &str) -> &'a str {
    let start = page
        .find(marker)
        .unwrap_or_else(|| panic!("{marker} in {page}"))
        + marker.len();
    &page[start..start + 36]
}

/// Auth's root, and each page's path ending in a slash, lead to the settings. A
/// browser without a session sees each page offer sign-in, which comes back to the
/// page as it asked for it, under the pages' policy. Its forms change nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn settings_pages_ask_a_signed_out_browser_to_sign_in() {
    let replicas = Replicas::new().await;
    let browser = Browser::signed_out();
    let root = browser.visit(&replicas.a, ROOT).await;
    assert_eq!(root.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(redirect(&root), settings::HOME);
    for path in PAGES {
        let slashed = browser
            .visit(&replicas.a, &format!("{path}/?remove=1"))
            .await;
        assert_eq!(slashed.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
        assert_eq!(redirect(&slashed), format!("{path}?remove=1"));
        let response = browser
            .visit(&replicas.a, &format!("{path}?remove=1"))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(
            policy(&response).starts_with("default-src 'none'"),
            "{path}"
        );
        let page = html(response).await;
        assert!(
            page.contains("<h2>Sign in to see your settings</h2>"),
            "{page}"
        );
        let sign_in = format!(
            r#"href="/login?return_to={}%3Fremove%3D1""#,
            path.replace('/', "%2F")
        );
        assert!(page.contains(&sign_in), "{page}");

        let posted = browser
            .post(&replicas, path, &DeviceChange::SignOutOthers)
            .await;
        assert_eq!(posted.status(), StatusCode::UNAUTHORIZED, "{path}");
        let page = html(posted).await;
        assert!(
            page.contains("<h2>Sign in to see your settings</h2>"),
            "{page}"
        );
    }
}

/// A form from an older page, whose change no page knows, changes nothing and says
/// why, on every page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn settings_pages_refuse_forms_they_do_not_know() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    for path in PAGES {
        let stale = browser
            .submit(&replicas.b, path, &[("action", "everything")], OWN_PAGE)
            .await;
        assert_eq!(stale.status(), StatusCode::BAD_REQUEST, "{path}");
        let page = html(stale).await;
        assert!(
            page.contains("This page was out of date. Try again."),
            "{page}"
        );
    }
}

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

/// A change that needs a recent passkey confirmation asks the SDK for one while the
/// session has none. Posted anyway, it is refused, and its row opens again, with
/// what was typed, to ask once more. A confirmed session makes it at once.
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
    assert!(
        page.contains(&format!("<strong>{address}</strong>")),
        "{page}"
    );
    assert!(page.contains("Waiting for confirmation"), "{page}");

    let id = id_after(&page, r#"name="remove" value=""#)
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
    assert!(
        page.contains(&format!("<strong>{second}</strong>")),
        "{page}"
    );
    assert!(
        page.contains("Primary: receives security notices"),
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
    let secret = std::env::temp_dir().join(format!("piquel-settings-secret-{}", TokenId::new()));
    std::fs::write(&secret, "secret").expect("provider secret");
    let mut config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    config
        .federation
        .providers
        .insert(Provider::GitHub, ProviderConfig::test(&secret));
    // The replicas read the secret as they start.
    let replicas = Replicas::of(&config).await;
    std::fs::remove_file(&secret).expect("provider secret removed");
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
/// time. Reporting one opens its confirmation first, and a report goes on to what
/// it left to undo, on the page it was made from. A report the account did not
/// make shows nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn history_reports_need_confirmation_and_cannot_be_forged() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let address = format!("{}@example.com", browser.user_id);
    let add = EmailChange::Add {
        email: address.clone(),
    };
    browser.post(&replicas, settings::EMAILS, &add).await;
    let page = html(browser.visit(&replicas.a, settings::HISTORY).await).await;
    assert!(!page.contains("Secure your account?"), "{page}");
    let marker = r#"name="report" value=""#;
    let added: EventId = id_after(&page, marker).parse().expect("newest entry");
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
    let signed_in: EventId = id_after(&page, marker).parse().expect("older entry");

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
/// Neither another account nor a token that does not match can.
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
    let id = id_after(&page, r#"name="remove" value=""#)
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
    assert!(html(refused).await.contains(r#"role="alert""#));

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
