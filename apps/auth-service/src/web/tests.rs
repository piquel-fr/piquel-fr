//! The pages through the whole service, as a browser uses them: navigations, and the
//! forms it posts with the headers browsers send.

use crate::{
    routes,
    tests::{Browser, MAX_RESPONSE_BYTES, Replicas, location, parameter, register, registration},
};
use axum::{
    body::to_bytes,
    http::{Method, StatusCode, header},
    response::Response,
};
use piquel_common::clients::{ClientKind, ClientRegistration};
use url::{Position, Url, form_urlencoded};

/// A PKCE `S256` challenge (RFC 7636 appendix B). No test redeems its code.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// What a form on one of auth's pages sends: they have `Referrer-Policy: no-referrer`,
/// so the browser sends `Origin: null`.
const OWN_PAGE: &[(&str, &str)] = &[("sec-fetch-site", "same-origin"), ("origin", "null")];

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
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client.id.as_str())
            .append_pair("redirect_uri", self.client.redirect_uris[0].as_str())
            .append_pair("scope", "openid profile")
            .append_pair("state", "page-test")
            .append_pair("code_challenge", CHALLENGE)
            .append_pair("code_challenge_method", "S256")
            .finish();
        let page = location(&self.visit(routes::oidc::AUTHORIZE, &query).await);
        assert_eq!(page.path(), routes::page::CONSENT);
        page
    }
}

/// `response`'s Content-Security-Policy.
fn policy(response: &Response) -> &str {
    response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .expect("CSP is text")
}

/// `response`'s body, as text.
async fn html(response: Response) -> String {
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
        let page = location(&harness.visit(routes::oidc::LOGOUT, &query).await);
        assert_eq!(page.path(), routes::page::LOGOUT);
        let response = harness.follow(&page).await;
        assert_eq!(response.status(), StatusCode::OK, "{state:?}");
        let policy = policy(&response).to_owned();
        assert!(
            policy.ends_with("form-action 'self' https://client.example"),
            "{policy}"
        );
        let html = html(response).await;
        assert!(html.contains("<h1>Ready to sign out?</h1>"), "{html}");
        let field = format!(r#"<input type="hidden" name="state" value="{state}">"#);
        assert!(html.contains(&field), "{html}");

        let fields: Vec<(String, String)> = page.query_pairs().into_owned().collect();
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
        let (status, _) = harness
            .browser
            .call(&harness.replicas.a, Method::GET, routes::passkey::SESSION)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{state:?}");
    }
}
