//! The admin dashboard through auth's two listeners, as a browser uses them:
//! signing in by auth's handoff page, the dashboard's own confirmation, and the
//! admin listener's security layer.

use crate::{
    AdminService, AuthConfig, DashboardConfig,
    account::AccountService,
    admin::DashboardSignIn,
    passkey::AdminProof,
    routes,
    security::{BrowserCookie, RequestContext},
    tests::{
        AUTH_ORIGIN, Browser, OWN_PAGE, Replicas, cookie, html, location, operator, parameter,
        policy, redirect,
    },
};
use axum::{
    Router,
    http::{StatusCode, header},
    response::Response,
};
use chrono::Utc;
use piquel_common::{AccountStatus, AuthenticationMethod, UserId};
use piquel_repository::Database;
use piquel_ui::{Checkbox, HandoffQuery};
use std::net::SocketAddr;
use url::{Position, Url};

/// The dashboard's origin in these scenarios.
const DASHBOARD: &str = "https://admin.piquel.fr";

/// Auth, with a dashboard on its admin listener.
struct Harness {
    /// Auth's public listener.
    auth: Replicas,
    /// The admin listener.
    dashboard: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds auth and its dashboard over the test database.
    async fn new() -> Self {
        let mut config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
        config.dashboard = Some(DashboardConfig {
            listener: SocketAddr::from(([127, 0, 0, 1], 0)),
            origin: DASHBOARD.parse().expect("dashboard origin"),
        });
        Self {
            auth: Replicas::of(&config).await,
            dashboard: Replicas::dashboard(&config).await,
            database: Replicas::database().await,
        }
    }

    /// A browser signed in to auth with a passkey, of a new administrator.
    async fn admin(&self) -> Browser {
        let browser = Browser::new_account(&self.database).await;
        self.grant(browser.user_id).await;
        browser
    }

    /// Makes `user_id` an administrator, from the CLI.
    async fn grant(&self, user_id: UserId) {
        AdminService::new(self.database.clone())
            .grant_administrator(&operator(), user_id)
            .await
            .expect("grant");
    }

    /// Visits the dashboard's `path` as `browser`.
    async fn visit(&self, browser: &Browser, path: &str) -> Response {
        browser
            .visit(&self.dashboard, &format!("{DASHBOARD}{path}"))
            .await
    }

    /// Follows `response`'s redirect to auth as `browser`.
    async fn to_auth(&self, browser: &Browser, response: &Response) -> Response {
        let target = location(response);
        assert_eq!(target.origin().ascii_serialization(), AUTH_ORIGIN);
        browser
            .visit(&self.auth.a, &target[Position::BeforePath..])
            .await
    }

    /// Opens the dashboard's `path` in a browser of its own, which goes through
    /// the handoff page as `auth`'s browser: the dashboard's browser, holding the
    /// state of its sign-in, and auth's answer.
    async fn hand_off(&self, auth: &Browser, path: &str) -> (Browser, Response) {
        let started = self.visit(&Browser::signed_out(), path).await;
        assert_eq!(started.status(), StatusCode::SEE_OTHER);
        let handoff = location(&started);
        assert_eq!(handoff.path(), routes::page::ADMIN);
        assert_eq!(parameter(&handoff, "return_to"), path);
        let (state, _) = cookie(&started, BrowserCookie::DashboardState);
        let dashboard = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, state);
        (dashboard, self.to_auth(auth, &started).await)
    }

    /// Signs `auth`'s browser in to the dashboard, which opens its `path`: the
    /// dashboard's browser, holding its session.
    async fn sign_in(&self, auth: &Browser, path: &str) -> Browser {
        let (dashboard, handed) = self.hand_off(auth, path).await;
        self.redeem(&dashboard, &location(&handed), path).await
    }

    /// Redeems the handoff `code_url` in the dashboard's `browser`, which then goes
    /// on to `path`: the browser, holding the dashboard's session.
    async fn redeem(&self, browser: &Browser, code_url: &Url, path: &str) -> Browser {
        assert_eq!(code_url.origin().ascii_serialization(), DASHBOARD);
        assert_eq!(code_url.path(), routes::dashboard::SIGN_IN);
        let signed_in = browser.visit(&self.dashboard, code_url.as_str()).await;
        assert_eq!(redirect(&signed_in), path);
        let (session, _) = cookie(&signed_in, BrowserCookie::Dashboard);
        let (state, _) = cookie(&signed_in, BrowserCookie::DashboardState);
        assert_eq!(state, "", "the state is done with");
        Browser::signed_out().with_cookie(BrowserCookie::Dashboard, session)
    }
}

/// An administrator's passkey session signs in to the dashboard through auth's
/// handoff page, silently. The code works once, only in the browser holding the
/// state it was bound to. Every page loads no script, and posts only to itself.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_hands_off_through_auth_once() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let (dashboard, handed) = harness.hand_off(&admin, "/users").await;
    let code_url = location(&handed);
    let elsewhere = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, "AAAA");
    let refused = elsewhere.visit(&harness.dashboard, code_url.as_str()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "another browser");
    let signed_in = harness.redeem(&dashboard, &code_url, "/users").await;
    let replayed = dashboard.visit(&harness.dashboard, code_url.as_str()).await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST, "once only");

    let page = harness.visit(&signed_in, "/users").await;
    assert_eq!(page.status(), StatusCode::OK);
    let csp = policy(&page).to_owned();
    let handoff = format!("form-action 'self' {AUTH_ORIGIN}{};", routes::page::ADMIN);
    assert!(csp.contains(&handoff), "{csp}");
    assert!(!csp.contains("script-src"), "{csp}");
    let handle = format!("@browser-{}", &admin.user_id.to_string()[24..]);
    assert!(
        html(page).await.contains(&handle),
        "the bar names the administrator"
    );
}

/// A dashboard session lasts while its auth session does, and the
/// administrator's rights are checked again on every request.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_dashboard_rests_on_the_auth_session_and_live_rights() {
    let harness = Harness::new().await;
    let signed_out = harness.admin().await;
    let dashboard = harness.sign_in(&signed_out, "/users").await;
    let mut tx = harness.database.begin().await.expect("transaction");
    crate::tests::sign_out(&mut tx, signed_out.user_id, signed_out.session_id)
        .await
        .expect("sign out");
    tx.commit().await.expect("commit");
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(
        location(&page).path(),
        routes::page::ADMIN,
        "signs in again"
    );

    let revoked = harness.admin().await;
    let dashboard = harness.sign_in(&revoked, "/users").await;
    // Another administrator, so the rights revoked are not the last.
    harness.admin().await;
    AdminService::new(harness.database.clone())
        .revoke_administrator(&operator(), revoked.user_id)
        .await
        .expect("revoke");
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(page.status(), StatusCode::FORBIDDEN);
    assert!(html(page).await.contains("This account has no access"));
}

/// A change needs the dashboard's own passkey confirmation: a passkey sign-in
/// to auth moments ago does not count. The page asks auth's handoff page for
/// one, which asks for a passkey proof whose form may go on to the dashboard. A
/// proof of the session handing off confirms the dashboard; one of another
/// session does not.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_change_needs_a_confirmation_done_for_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = Browser::new_account(&harness.database).await;
    let dashboard = harness.sign_in(&admin, "/users").await;
    let disable = format!("/users/{}/disable", user.user_id);
    let asked = harness.visit(&dashboard, &disable).await;
    let handoff = location(&asked);
    assert_eq!(handoff.path(), routes::page::ADMIN);
    assert_eq!(parameter(&handoff, "confirm"), "on");
    let (state, _) = cookie(&asked, BrowserCookie::DashboardState);
    let page = harness.to_auth(&admin, &asked).await;
    assert_eq!(page.status(), StatusCode::OK);
    let csp = policy(&page).to_owned();
    assert!(
        csp.contains(&format!("form-action 'self' {DASHBOARD}")),
        "{csp}"
    );
    assert!(
        html(page)
            .await
            .contains(r#"data-passkey-assertion="/admin/proof""#)
    );

    let sign_in = DashboardSignIn::new(
        harness.database.clone(),
        AUTH_ORIGIN.parse().expect("auth origin"),
        DASHBOARD.parse().expect("dashboard origin"),
    );
    let owner = admin.owner(&harness.database).await;
    let query = HandoffQuery {
        state: state.to_owned(),
        return_to: disable.clone(),
        confirm: Checkbox(true),
    };
    let other = Browser::sign_in(&harness.database, admin.user_id).await;
    let elsewhere = AdminProof::unverified(other.session_id, Utc::now());
    let refused = sign_in.hand_off(&owner, &query, Some(elsewhere)).await;
    assert!(refused.is_err(), "a proof of another session");
    let refused = sign_in.hand_off(&owner, &query, None).await;
    assert!(refused.is_err(), "no proof");
    let proof = AdminProof::unverified(admin.session_id, Utc::now());
    let code_url = sign_in
        .hand_off(&owner, &query, Some(proof))
        .await
        .expect("handed off");
    let browser = dashboard.with_cookie(BrowserCookie::DashboardState, state);
    let confirmed = harness.redeem(&browser, &code_url, &disable).await;
    let form = harness.visit(&confirmed, &disable).await;
    assert_eq!(form.status(), StatusCode::OK);
    let done = confirmed
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}{disable}"),
            &[("reason", "Browser test")],
            OWN_PAGE,
        )
        .await;
    assert_eq!(redirect(&done), format!("/users/{}", user.user_id));
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Disabled);
}

/// An account's page lists its passkeys by ID and when each was added, never by
/// name, which whoever used a recovery's link chose.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_accounts_page_names_no_passkey() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let passkey = harness
        .database
        .passkeys()
        .insert(&crate::tests::unusable_passkey(owner.user_id))
        .await
        .expect("passkey");
    let account = format!("/users/{}", owner.user_id);
    let dashboard = harness.sign_in(&admin, &account).await;
    let page = html(harness.visit(&dashboard, &account).await).await;
    assert!(page.contains(&passkey.id.to_string()), "{page}");
    assert!(!page.contains(&passkey.friendly_name), "{page}");
}

/// Only an administrator signed in with a passkey is handed off: anyone else is
/// told they have no access, and a social sign-in signs in with a passkey first,
/// coming back to the handoff, which the sign-in page's forms may then follow to
/// the dashboard.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_administrators_signed_in_with_a_passkey_are_handed_off() {
    let harness = Harness::new().await;
    let user = Browser::new_account(&harness.database).await;
    let (_, refused) = harness.hand_off(&user, "/users").await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(refused.headers().get(header::LOCATION).is_none());
    assert!(html(refused).await.contains("This account has no access"));

    let social = Browser::new_account(&harness.database).await;
    harness.grant(social.user_id).await;
    let social = Browser::sign_in_with(
        &harness.database,
        social.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let (_, asked) = harness.hand_off(&social, "/users").await;
    let login = Url::parse(AUTH_ORIGIN)
        .and_then(|auth| auth.join(redirect(&asked)))
        .expect("sign-in URL");
    assert_eq!(login.path(), routes::page::LOGIN);
    assert_eq!(parameter(&login, "acr"), "phr");
    assert!(parameter(&login, "return_to").starts_with(routes::page::ADMIN));
    let page = social
        .visit(&harness.auth.a, &login[Position::BeforePath..])
        .await;
    let csp = policy(&page).to_owned();
    assert!(
        csp.contains(&format!("form-action 'self' {DASHBOARD}")),
        "{csp}"
    );
    let page = social.visit(&harness.auth.a, routes::page::LOGIN).await;
    assert!(!policy(&page).contains(DASHBOARD), "only on its way there");
}

/// A change's form is shown only while the dashboard's confirmation has time
/// left to fill it in, but may be posted as long as the confirmation lasts.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_form_shown_in_time_may_be_posted_until_the_confirmation_ends() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = Browser::new_account(&harness.database).await;
    let disable = format!("/users/{}/disable", user.user_id);
    let sign_in = DashboardSignIn::new(
        harness.database.clone(),
        AUTH_ORIGIN.parse().expect("auth origin"),
        DASHBOARD.parse().expect("dashboard origin"),
    );
    let state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let query = HandoffQuery {
        state: state.to_owned(),
        return_to: disable.clone(),
        confirm: Checkbox(true),
    };
    // Ninety seconds left: less than a form needs, more than a post does.
    let ninety_seconds_left = Utc::now() - chrono::Duration::seconds(210);
    let proof = AdminProof::unverified(admin.session_id, ninety_seconds_left);
    let code_url = sign_in
        .hand_off(&admin.owner(&harness.database).await, &query, Some(proof))
        .await
        .expect("handed off");
    let browser = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, state);
    let confirmed = harness.redeem(&browser, &code_url, &disable).await;
    let form = harness.visit(&confirmed, &disable).await;
    assert_eq!(
        location(&form).path(),
        routes::page::ADMIN,
        "too late to show"
    );
    let done = confirmed
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}{disable}"),
            &[("reason", "Posted in time")],
            OWN_PAGE,
        )
        .await;
    assert_eq!(redirect(&done), format!("/users/{}", user.user_id));
}

/// The admin listener serves only the dashboard's host, takes forms only from
/// its own pages, and signing out ends the dashboard's session alone.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_admin_listener_keeps_to_its_host_forms_and_session() {
    let harness = Harness::new().await;
    let anyone = Browser::signed_out();
    let misrouted = anyone.visit(&harness.dashboard, "/users").await;
    assert_eq!(misrouted.status(), StatusCode::MISDIRECTED_REQUEST);
    let elsewhere = anyone
        .visit(&harness.dashboard, "https://auth.piquel.fr/users")
        .await;
    assert_eq!(elsewhere.status(), StatusCode::MISDIRECTED_REQUEST);

    let admin = harness.admin().await;
    let dashboard = harness.sign_in(&admin, "/users").await;
    let sign_out = format!("{DASHBOARD}/sign-out");
    let foreign = [("sec-fetch-site", "same-site"), ("origin", AUTH_ORIGIN)];
    let refused = dashboard
        .submit(&harness.dashboard, &sign_out, &[], &foreign)
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let signed_out = dashboard
        .submit(&harness.dashboard, &sign_out, &[], OWN_PAGE)
        .await;
    assert_eq!(redirect(&signed_out), "/sign-out");
    assert_eq!(cookie(&signed_out, BrowserCookie::Dashboard).0, "");
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(location(&page).path(), routes::page::ADMIN, "signed out");
    AccountService::new(harness.database.clone())
        .owner(RequestContext::TEST, &admin.headers())
        .await
        .expect("lookup")
        .expect("still signed in to Piquel");
}
