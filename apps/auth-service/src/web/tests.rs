//! The pages through the whole service, as a browser uses them: navigations, and the
//! forms it posts with the headers browsers send.

use super::WebApplication;
use crate::{
    routes::{
        self,
        page::{
            ROOT,
            developers::{self, APP, APP_SECRETS, APP_SETTINGS},
            settings,
        },
    },
    security::BrowserCookie,
    tests::{
        Browser, MAX_RESPONSE_BYTES, OWN_PAGE, Replicas, location, parameter, redirect, register,
        registration,
    },
};
use axum::{
    body::to_bytes,
    http::{StatusCode, header},
    response::Response,
};
use piquel_common::{
    ClientId,
    clients::{ClientKind, ClientRegistration},
};
use piquel_ui::{DeviceChange, Section};
use serde::Serialize;
use url::{Position, Url, form_urlencoded};

/// A PKCE `S256` challenge (RFC 7636 appendix B). No test redeems its code.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Two replicas, a signed-in browser, and an untrusted client.
struct Harness {
    /// The service.
    replicas: Replicas,
    /// The signed-in browser.
    browser: Browser,
    /// The client, which needs consent.
    client: ClientRegistration,
}

impl Harness {
    /// Registers a client calling back to `origin`, and signs a new account in.
    async fn new(origin: &str) -> Self {
        let database = Replicas::database().await;
        let client = registration(ClientKind::Public, origin);
        register(&database, &client).await.expect("client");
        Self {
            browser: Browser::new_account(&database).await,
            replicas: Replicas::new().await,
            client,
        }
    }

    /// Visits `path` with `query` on replica `a`.
    async fn visit(&self, path: &str, query: &str) -> Response {
        self.browser
            .visit(&self.replicas.a, &format!("{path}?{query}"))
            .await
    }

    /// Visits the page `url` names, as a redirect sends the browser there.
    async fn follow(&self, url: &Url) -> Response {
        self.browser
            .visit(&self.replicas.a, &url[Position::BeforePath..])
            .await
    }

    /// Posts the form `fields` to `path` on replica `b`, with `headers`.
    async fn submit(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Response {
        self.browser
            .submit(&self.replicas.b, path, fields, headers)
            .await
    }

    /// Starts an authorization as the client, and returns the consent page it lands on.
    async fn consent_page(&self) -> Url {
        let authorize = authorize(&self.client, &[]);
        let page = location(&self.browser.visit(&self.replicas.a, &authorize).await);
        assert_eq!(page.path(), routes::page::CONSENT);
        page
    }
}

/// The authorization request of `client`, asking for its profile with `extra`
/// parameters, such as `acr_values`.
pub(super) fn authorize(client: &ClientRegistration, extra: &[(&str, &str)]) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client.id.as_str())
        .append_pair("redirect_uri", client.redirect_uris[0].as_str())
        .append_pair("scope", "openid profile")
        .append_pair("state", "page-test")
        .append_pair("code_challenge", CHALLENGE)
        .append_pair("code_challenge_method", "S256")
        .extend_pairs(extra.iter().copied())
        .finish();
    format!("{}?{query}", routes::oidc::AUTHORIZE)
}

impl Browser {
    /// This browser as it follows `response`'s redirect, holding the notice it set.
    pub(super) fn following(&self, response: &Response) -> Self {
        let (notice, _) = cookie(response, BrowserCookie::Notice);
        self.with_cookie(BrowserCookie::Notice, notice)
    }

    /// Posts `change` to the page at `path` on replica `b`, as the page's form sends
    /// it.
    pub(super) async fn post(
        &self,
        replicas: &Replicas,
        path: &str,
        change: &impl Serialize,
    ) -> Response {
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
pub(super) fn cookie(response: &Response, name: BrowserCookie) -> (&str, &str) {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .find_map(|cookie| cookie.strip_prefix(name.as_str())?.strip_prefix('='))
        .and_then(|cookie| cookie.split_once(';'))
        .unwrap_or_else(|| panic!("{name} is set"))
}

/// The value `page` writes right after `marker`, up to the next quote or tag, such
/// as the ID a form sends.
pub(super) fn value_after<'a>(page: &'a str, marker: &str) -> &'a str {
    let start = page
        .find(marker)
        .unwrap_or_else(|| panic!("{marker} in {page}"))
        + marker.len();
    page[start..].split(['"', '<']).next().unwrap_or_default()
}

/// Every account page's path, and its section: the settings tabs, the console's
/// own pages, and the pages of the app `app`.
fn account_pages(app: &ClientId) -> Vec<(String, Section)> {
    let settings = [
        settings::HOME,
        settings::EMAILS,
        settings::SESSIONS,
        settings::HISTORY,
    ]
    .map(|path| (path.to_owned(), Section::Account));
    let console =
        [developers::HOME, developers::NEW].map(|path| (path.to_owned(), Section::Developers));
    let app = [APP, APP_SETTINGS, APP_SECRETS]
        .map(|route| (developers::of(route, app), Section::Developers));
    settings.into_iter().chain(console).chain(app).collect()
}

/// `response`'s Content-Security-Policy.
pub(super) fn policy(response: &Response) -> &str {
    response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .expect("CSP is text")
}

/// `response`'s body, as text.
pub(super) async fn html(response: Response) -> String {
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("body");
    String::from_utf8(body.to_vec()).expect("UTF-8 page")
}

/// The consent page shows what the application asks for. Its form decides once, and
/// only from auth's own pages and within the body limit; its policy lets the form
/// redirect to the application.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn consent_page_decides_from_its_own_form() {
    let harness = Harness::new("https://client.example").await;
    let page = harness.consent_page().await;
    let response = harness.follow(&page).await;
    assert_eq!(response.status(), StatusCode::OK);
    let policy = policy(&response).to_owned();
    assert!(
        policy.starts_with("default-src 'none'; style-src https://auth.piquel.fr/assets/style."),
        "{policy}"
    );
    assert!(
        policy.ends_with("form-action 'self' https://client.example"),
        "{policy}"
    );
    let html = html(response).await;
    assert!(html.contains("<h1>Continue to Test app.</h1>"), "{html}");
    assert!(
        html.contains("<li>Your username and display name</li>"),
        "{html}"
    );

    let transaction = parameter(&page, "transaction");
    let approve = [
        ("transaction", transaction.as_str()),
        ("decision", "approve"),
    ];
    // Neither another site's form nor a body over the limit decides.
    let foreign = [
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://evil.example"),
    ];
    assert_eq!(
        harness
            .submit(routes::page::CONSENT, &approve, &foreign)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let padding = "a".repeat(64 * 1024);
    let oversized = [approve[0], approve[1], ("padding", padding.as_str())];
    assert_eq!(
        harness
            .submit(routes::page::CONSENT, &oversized, OWN_PAGE)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    let approved = harness
        .submit(routes::page::CONSENT, &approve, OWN_PAGE)
        .await;
    assert_eq!(approved.status(), StatusCode::SEE_OTHER);
    let callback = location(&approved);
    assert_eq!(
        &callback[..Position::AfterPath],
        harness.client.redirect_uris[0].as_str()
    );
    assert!(!parameter(&callback, "code").is_empty(), "{callback}");
    let replayed = harness
        .submit(routes::page::CONSENT, &approve, OWN_PAGE)
        .await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
}

/// No Content-Security-Policy can name a native application's loopback callback, or
/// a host with characters host sources lack, so the consent form may post only to
/// auth, then links on to the callback rather than redirecting, which the browser
/// would block.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn consent_links_on_to_callbacks_no_policy_can_name() {
    for origin in [
        "http://[::1]:8080",
        "http://127.0.0.1:8080",
        "https://client_test.example",
    ] {
        let harness = Harness::new(origin).await;
        let page = harness.consent_page().await;
        let response = harness.follow(&page).await;
        let policy = policy(&response).to_owned();
        assert!(policy.ends_with("form-action 'self'"), "{origin}: {policy}");

        let transaction = parameter(&page, "transaction");
        let approve = [
            ("transaction", transaction.as_str()),
            ("decision", "approve"),
        ];
        let approved = harness
            .submit(routes::page::CONSENT, &approve, OWN_PAGE)
            .await;
        assert_eq!(approved.status(), StatusCode::OK, "{origin}");
        let html = html(approved).await;
        let link = format!(r#"<a class="button" href="{origin}/callback?code="#);
        assert!(html.contains(&link), "{html}");
    }
}

/// The logout page confirms an application's logout request: its form ends the
/// session and sends the browser where the application asked, with its `state`,
/// even an empty one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn logout_page_ends_the_session_from_its_own_form() {
    for state in ["bye", ""] {
        let harness = Harness::new("https://client.example").await;
        let post_logout = harness.client.post_logout_uris[0].as_str();
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", harness.client.id.as_str())
            .append_pair("post_logout_redirect_uri", post_logout)
            .append_pair("state", state)
            .finish();
        let confirm = location(&harness.visit(routes::oidc::LOGOUT, &query).await);
        assert_eq!(confirm.path(), routes::page::LOGOUT);
        let response = harness.follow(&confirm).await;
        assert_eq!(response.status(), StatusCode::OK, "{state:?}");
        let policy = policy(&response).to_owned();
        assert!(
            policy.ends_with("form-action 'self' https://client.example"),
            "{policy}"
        );
        let page = html(response).await;
        assert!(page.contains("<h1>Ready to sign out?</h1>"), "{page}");
        let field = format!(r#"<input type="hidden" name="state" value="{state}">"#);
        assert!(page.contains(&field), "{page}");

        let fields: Vec<(String, String)> = confirm.query_pairs().into_owned().collect();
        let fields: Vec<_> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let signed_out = harness
            .submit(routes::page::LOGOUT, &fields, OWN_PAGE)
            .await;
        assert_eq!(signed_out.status(), StatusCode::SEE_OTHER, "{state:?}");
        assert_eq!(
            location(&signed_out).as_str(),
            format!("{post_logout}?state={state}")
        );
        let cookie = signed_out.headers()[header::SET_COOKIE]
            .to_str()
            .expect("Set-Cookie is text");
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
        let after = html(
            harness
                .browser
                .visit(&harness.replicas.a, settings::HOME)
                .await,
        )
        .await;
        assert!(
            after.contains("<h2>Sign in to see your settings</h2>"),
            "{state:?}: {after}"
        );
    }
}

/// Auth's root, and each account page's path ending in a slash, an app's included,
/// lead to the page, whatever the method. A browser without a session sees each
/// page offer sign-in, which comes back to the page as it asked for it, under the
/// pages' policy. Its forms change nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_pages_ask_a_signed_out_browser_to_sign_in() {
    let replicas = Replicas::new().await;
    let browser = Browser::signed_out();
    let root = browser.visit(&replicas.a, ROOT).await;
    assert_eq!(root.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(redirect(&root), settings::HOME);
    let unknown = "c_unknown".parse().expect("client ID");
    for (path, section) in account_pages(&unknown) {
        let heading = match section {
            Section::Account => "<h2>Sign in to see your settings</h2>",
            Section::Developers => "<h2>Sign in to manage your apps</h2>",
        };
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
        assert!(page.contains(heading), "{page}");
        let sign_in = format!(
            r#"href="/login?return_to={}%3Fremove%3D1""#,
            path.replace('/', "%2F")
        );
        assert!(page.contains(&sign_in), "{page}");

        let posted = browser
            .post(&replicas, &path, &DeviceChange::SignOutOthers)
            .await;
        assert_eq!(posted.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert!(html(posted).await.contains(heading), "{path}");
        // Only a page's route takes forms from auth's own pages.
        let posted = browser
            .post(&replicas, &format!("{path}/"), &DeviceChange::SignOutOthers)
            .await;
        assert_eq!(posted.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
        assert_eq!(redirect(&posted), path);
    }
}

/// A form from an older page, whose change no page knows, changes nothing and says
/// why, on every account page, an app's included.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_pages_refuse_forms_they_do_not_know() {
    let replicas = Replicas::new().await;
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let app = browser
        .register_app(&database, ClientKind::Confidential, "https://stale.example")
        .await;
    for (path, _) in account_pages(&app) {
        let stale = browser
            .submit(&replicas.b, &path, &[("action", "everything")], OWN_PAGE)
            .await;
        assert_eq!(stale.status(), StatusCode::BAD_REQUEST, "{path}");
        let page = html(stale).await;
        assert!(
            page.contains("This page was out of date. Try again."),
            "{page}"
        );
    }
}

/// Every page the router registers is one the security layer classifies as a page,
/// and the other way around.
#[test]
fn every_page_is_mounted_and_classified() {
    let mounted: Vec<_> = WebApplication::pages().map(|(path, ..)| path).into();
    assert_eq!(mounted, routes::page::ALL);
}
