//! The pages through the whole service, as a browser uses them: navigations, and the
//! forms it posts with the headers browsers send.

use super::WebApplication;
use crate::{
    routes::{
        self,
        page::{
            REGISTER, ROOT,
            developers::{self, APP, APP_SECRETS, APP_SETTINGS},
            settings,
        },
    },
    security::BrowserCookie,
    tests::{
        Browser, OWN_PAGE, Replicas, WEB_ORIGIN, change, cookie, html, location, parameter, policy,
        redirect, register, registration,
    },
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use piquel_common::{
    ClientId,
    clients::{ClientKind, ClientOwner, ClientRegistration},
};
use piquel_ui::{DeviceChange, Section};
use serde::Serialize;
use tower::ServiceExt;
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

    /// Posts a page's upload form to `path` on `replicas`' second replica, as
    /// `multipart/form-data`: the `change` it names, and `file` in the file input
    /// `input`.
    pub(super) async fn upload(
        &self,
        replicas: &Replicas,
        path: &str,
        change: &impl Serialize,
        (input, file): (&str, &[u8]),
    ) -> Response {
        const BOUNDARY: &str = "picture-upload-boundary";
        let encoded = serde_urlencoded::to_string(change).expect("change");
        let fields: Vec<(String, String)> = serde_urlencoded::from_str(&encoded).expect("fields");
        let mut body = Vec::new();
        for (name, value) in &fields {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{input}\"; filename=\"picture\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(file);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::COOKIE, &self.cookie)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            );
        for (name, value) in OWN_PAGE {
            request = request.header(*name, *value);
        }
        replicas
            .b
            .clone()
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("response")
    }
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
        settings::DATA,
    ]
    .map(|path| (path.to_owned(), Section::Account));
    let console =
        [developers::HOME, developers::NEW].map(|path| (path.to_owned(), Section::Developers));
    let app = [APP, APP_SETTINGS, APP_SECRETS]
        .map(|route| (developers::of(route, app), Section::Developers));
    settings.into_iter().chain(console).chain(app).collect()
}

/// The consent page shows what the application asks for, and nothing about who
/// registered one operators manage. Its form decides once, and
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
    assert!(html.contains("<h1>Continue to Test app?</h1>"), "{html}");
    assert!(
        html.contains(
            r#"<span class="text">Your username, display name and profile picture</span></li>"#
        ),
        "{html}"
    );
    assert!(!html.contains("Unverified"), "{html}");

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

/// An app an account registered says so on its consent page: where it sends the
/// browser, who registered it and that nobody verified it, beside the account
/// signed in, which can switch to another one and come back to the authorization.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn consent_page_says_who_asks_and_who_answers() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let client = registration(ClientKind::Public, "https://notes.example");
    change(&database, async |registry| {
        registry
            .create(ClientOwner::Account(owner.user_id), &client, None)
            .await
    })
    .await
    .expect("client");
    let harness = Harness {
        browser: Browser::new_account(&database).await,
        replicas: Replicas::new().await,
        client,
    };
    let handle = async |browser: &Browser| {
        let user = database.users().find_by_id(browser.user_id).await;
        user.expect("lookup").expect("account").handle
    };
    let page = harness.consent_page().await;
    let html = html(harness.follow(&page).await).await;
    for shown in [
        "You’ll be sent to <strong>notes.example</strong>".to_owned(),
        format!("Unverified app, registered by @{}", handle(&owner).await),
        format!("Signed in as @{}.", handle(&harness.browser).await),
    ] {
        assert!(html.contains(&shown), "{shown}: {html}");
    }

    let query = value_after(&html, &format!(r#"action="{}?"#, routes::page::LOGIN));
    let sign_in = format!("{}?{query}", routes::page::LOGIN);
    assert_eq!(
        query,
        format!("transaction={}", parameter(&page, "transaction"))
    );
    let switched = harness
        .submit(&sign_in, &[("action", "switch_account")], OWN_PAGE)
        .await;
    assert_eq!(switched.status(), StatusCode::SEE_OTHER);
    assert_eq!(redirect(&switched), sign_in);
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
            after.contains("<h1>Sign in to see your settings</h1>"),
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
            Section::Account => "<h1>Sign in to see your settings</h1>",
            Section::Developers => "<h1>Sign in to manage your apps</h1>",
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

/// Piquel's policies are piquel.fr's: every page's footer links them there, the
/// registration form agrees to them there, and discovery advertises them there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_and_discovery_link_piquel_fr_policies() {
    let replicas = Replicas::new().await;
    let browser = Browser::signed_out();
    let page = html(browser.visit(&replicas.a, REGISTER).await).await;
    for path in ["/privacy", "/terms"] {
        let link = format!(r#"href="{WEB_ORIGIN}{path}""#);
        assert_eq!(
            page.matches(&link).count(),
            2,
            "footer and agreement: {path}"
        );
    }
    let discovery = html(browser.visit(&replicas.a, routes::oidc::DISCOVERY).await).await;
    assert!(discovery.contains(&format!(r#""op_policy_uri":"{WEB_ORIGIN}/privacy""#)));
    assert!(discovery.contains(&format!(r#""op_tos_uri":"{WEB_ORIGIN}/terms""#)));
}
