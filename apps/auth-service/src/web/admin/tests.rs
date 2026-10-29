//! The admin dashboard through auth's two listeners, as a browser uses them:
//! signing in by auth's handoff page, the dashboard's own confirmation, and the
//! admin listener's security layer.

use crate::{
    AdminService, AuthConfig, DashboardConfig,
    account::AccountService,
    admin::DashboardSignIn,
    config::EmailConfig,
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
use chrono::{DateTime, Utc};
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
        Self::of(AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"))).await
    }

    /// Builds auth as `config` sets it up, and its dashboard, over the test
    /// database.
    async fn of(mut config: AuthConfig) -> Self {
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
        AdminService::new(self.database.clone(), true)
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

    /// Signs `auth`'s browser in to the dashboard, which opens its `path`, with a
    /// passkey proof of the handoff at `proved_at`: the dashboard's browser,
    /// holding its session.
    async fn confirmed(&self, auth: &Browser, path: &str, proved_at: DateTime<Utc>) -> Browser {
        let sign_in = DashboardSignIn::new(
            self.database.clone(),
            AUTH_ORIGIN.parse().expect("auth origin"),
            DASHBOARD.parse().expect("dashboard origin"),
        );
        let state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let query = HandoffQuery {
            state: state.to_owned(),
            return_to: path.to_owned(),
            confirm: Checkbox(true),
        };
        let proof = AdminProof::unverified(auth.session_id, proved_at);
        let code_url = sign_in
            .hand_off(&auth.owner(&self.database).await, &query, Some(proof))
            .await
            .expect("handed off");
        let browser = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, state);
        self.redeem(&browser, &code_url, path).await
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
    AdminService::new(harness.database.clone(), true)
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

/// While email is disabled, the Recover page says why the service refuses a
/// recovery whose link would only be mailed.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn recover_says_when_email_is_disabled() {
    let origin = AUTH_ORIGIN.parse().expect("auth origin");
    let mut config = AuthConfig::test(&origin);
    config.email = EmailConfig::test(&origin, false);
    let harness = Harness::of(config).await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let address = format!("{}@example.com", owner.user_id);
    crate::tests::verified_address(&harness.database, owner.user_id, &address, true).await;
    let recover = format!("/users/{}/recover", owner.user_id);
    let dashboard = harness.confirmed(&admin, &recover, Utc::now()).await;
    let url = format!("{DASHBOARD}{recover}");
    let reason = [("reason", "Lost every passkey")];
    let refused = dashboard
        .submit(&harness.dashboard, &url, &reason, OWN_PAGE)
        .await;
    assert!(html(refused).await.contains("email is disabled"));
}

/// An administrator removes the access of an app the account consented to, with
/// a reason, from its Connected apps page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_remove_an_accounts_app() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let client = crate::tests::registration(
        piquel_common::clients::ClientKind::Public,
        "https://client.example",
    );
    crate::tests::register(&harness.database, &client)
        .await
        .expect("register");
    let scopes = ["openid".to_owned()];
    harness
        .database
        .oidc()
        .save_consent(owner.user_id, &client.id, client.id.as_str(), &scopes)
        .await
        .expect("consent");
    let apps = format!("/users/{}/apps", owner.user_id);
    let dashboard = harness.confirmed(&admin, &apps, Utc::now()).await;
    let opened = format!("{apps}?remove={}", client.id);
    let page = html(harness.visit(&dashboard, &opened).await).await;
    assert!(page.contains("the owner’s approval again"), "{page}");
    assert!(
        page.contains(r#"name="reason""#),
        "a removal asks why: {page}"
    );

    let url = format!("{DASHBOARD}{apps}");
    let remove = [
        ("action", "remove"),
        ("client_id", client.id.as_str()),
        ("reason", "Reported as an impersonating app"),
    ];
    let done = dashboard
        .submit(&harness.dashboard, &url, &remove, OWN_PAGE)
        .await;
    assert_eq!(redirect(&done), apps);
    let page = html(harness.visit(&dashboard, &apps).await).await;
    assert!(
        page.contains("No app has access to this account."),
        "{page}"
    );
}

/// A change the service refuses shows the form again with what was typed: a
/// settings section reopens the refused row with its input and reason, which no
/// other form takes, and a change page keeps its fields.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_refused_change_keeps_what_was_typed() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let user = owner.user_id;
    let passkey = harness
        .database
        .passkeys()
        .insert(&crate::tests::unusable_passkey(user))
        .await
        .expect("passkey")
        .id
        .to_string();
    let sign_in = format!("/users/{user}/sign-in");
    let dashboard = harness.confirmed(&admin, &sign_in, Utc::now()).await;
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };

    let too_long = "x".repeat(81);
    let rename = [
        ("action", "rename"),
        ("id", passkey.as_str()),
        ("friendly_name", too_long.as_str()),
        ("reason", "Asked by email"),
    ];
    let refused = post(&sign_in, &rename).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = html(refused).await;
    assert!(page.contains(&format!(r#"value="{too_long}""#)), "{page}");
    assert!(page.contains(r#"value="Asked by email""#), "{page}");

    let first = format!("first-{user}@example.com");
    let primary = crate::tests::verified_address(&harness.database, user, &first, true).await;
    let second = format!("second-{user}@example.com");
    let second_id = crate::tests::verified_address(&harness.database, user, &second, false).await;
    let emails = format!("/users/{user}/emails");
    let primary = primary.to_string();
    let remove = [
        ("action", "remove"),
        ("id", primary.as_str()),
        ("reason", "Asked by phone"),
    ];
    let page = html(post(&emails, &remove).await).await;
    assert_eq!(
        page.matches(r#"value="Asked by phone""#).count(),
        1,
        "only the refused row keeps the reason: {page}"
    );
    let other = second_id.to_string();
    let long = "x".repeat(501);
    let primary = [
        ("action", "primary"),
        ("id", other.as_str()),
        ("reason", long.as_str()),
    ];
    let page = html(post(&emails, &primary).await).await;
    assert_eq!(
        page.matches(&format!(r#"value="{long}""#)).count(),
        1,
        "the refused Make primary keeps its own reason: {page}"
    );

    let handle = format!("/users/{user}/handle");
    let current = harness
        .database
        .users()
        .find_by_id(user)
        .await
        .expect("lookup")
        .expect("user")
        .handle
        .to_string();
    let same = [("handle", current.as_str()), ("reason", "Impersonation")];
    let page = html(post(&handle, &same).await).await;
    assert!(page.contains(&format!(r#"value="{current}""#)), "{page}");
    assert!(page.contains(r#"value="Impersonation""#), "{page}");
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
    // Ninety seconds left: less than a form needs, more than a post does.
    let ninety_seconds_left = Utc::now() - chrono::Duration::seconds(210);
    let confirmed = harness
        .confirmed(&admin, &disable, ninety_seconds_left)
        .await;
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

/// Recovering an account mails its primary verified address a link, which the
/// recovery pages then list, and undoing it cancels the unused link; both go on
/// to the account's page. Until then, the account's sign-in methods say no
/// passkey can be removed. An account whose link would not be mailed is left
/// alone, saying why.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn recoveries_are_started_and_undone_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let address = format!("{}@example.com", owner.user_id);
    crate::tests::verified_address(&harness.database, owner.user_id, &address, true).await;
    let recover = format!("/users/{}/recover", owner.user_id);
    let dashboard = harness.confirmed(&admin, &recover, Utc::now()).await;
    let page = html(harness.visit(&dashboard, &recover).await).await;
    assert!(page.contains("No recovery in the last 15 days."));
    let reason = [("reason", "Lost every passkey")];
    let post = async |path: &str| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, &reason, OWN_PAGE)
            .await
    };
    let account = format!("/users/{}", owner.user_id);
    assert_eq!(redirect(&post(&recover).await), account);
    let page = html(harness.visit(&dashboard, &recover).await).await;
    assert!(page.contains("Link sent, not used"), "{page}");
    let sign_in = format!("/users/{}/sign-in", owner.user_id);
    let page = html(harness.visit(&dashboard, &sign_in).await).await;
    assert!(
        page.contains("removed while the recovery can be cancelled"),
        "{page}"
    );

    let undo = format!("/users/{}/undo-recovery", owner.user_id);
    assert_eq!(redirect(&post(&undo).await), account);
    let page = html(harness.visit(&dashboard, &undo).await).await;
    assert!(page.contains("Cancelled"), "{page}");

    let unreachable = Browser::new_account(&harness.database).await;
    let recover = format!("/users/{}/recover", unreachable.user_id);
    let refused = html(post(&recover).await).await;
    assert!(refused.contains("would not be mailed"), "{refused}");
    let recent = AdminService::new(harness.database.clone(), true)
        .recent_recoveries(&operator(), unreachable.user_id)
        .await
        .expect("recoveries");
    assert!(recent.is_empty(), "nothing started");
}

/// An administrator changes an account's settings with the owner's own
/// operations, each with a reason: renaming and removing a passkey, and making
/// another address primary. The pages offer nothing that adds a way in, and a
/// change without a reason, or only the owner's, is refused. They also rename
/// the account's handle, under the owner's handle rules but without the cooldown.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_change_an_accounts_settings_with_a_reason() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let user = owner.user_id;
    let mut passkeys = Vec::new();
    for _ in 0..2 {
        let stored = harness
            .database
            .passkeys()
            .insert(&crate::tests::unusable_passkey(user))
            .await
            .expect("passkey");
        passkeys.push(stored.id.to_string());
    }
    let first = format!("first-{user}@example.com");
    crate::tests::verified_address(&harness.database, user, &first, true).await;
    let second = format!("second-{user}@example.com");
    let other = crate::tests::verified_address(&harness.database, user, &second, false).await;
    let sign_in = format!("/users/{user}/sign-in");
    let dashboard = harness.confirmed(&admin, &sign_in, Utc::now()).await;
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };

    let page = html(harness.visit(&dashboard, &sign_in).await).await;
    assert!(page.contains("Existing key"), "{page}");
    assert!(!page.contains("data-passkey-enroll"), "no passkey is added");
    let opened = format!("{sign_in}?rename={}", passkeys[0]);
    let page = html(harness.visit(&dashboard, &opened).await).await;
    assert!(
        page.contains(r#"name="reason""#),
        "a change asks why: {page}"
    );

    let rename = [
        ("action", "rename"),
        ("id", passkeys[0].as_str()),
        ("friendly_name", "Renamed by support"),
    ];
    let refused = post(&sign_in, &[rename.as_slice(), &[("reason", "")]].concat()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "no reason");
    let reason = ("reason", "Asked by email");
    let done = post(&sign_in, &[rename.as_slice(), &[reason]].concat()).await;
    assert_eq!(redirect(&done), sign_in);
    let remove = [("action", "remove"), ("id", passkeys[1].as_str()), reason];
    assert_eq!(redirect(&post(&sign_in, &remove).await), sign_in);
    let active = harness
        .database
        .passkeys()
        .list_active(user)
        .await
        .expect("passkeys");
    let names: Vec<_> = active
        .iter()
        .map(|key| key.friendly_name.as_str())
        .collect();
    assert_eq!(names, ["Renamed by support"]);
    let link = [("action", "link"), ("provider", "github"), reason];
    let refused = html(post(&sign_in, &link).await).await;
    assert!(
        refused.contains("Only the account&#39;s owner")
            || refused.contains("Only the account's owner")
    );

    let emails = format!("/users/{user}/emails");
    let page = html(harness.visit(&dashboard, &emails).await).await;
    assert!(!page.contains("Add an address"), "no address is added");
    let other = other.to_string();
    let primary = [("action", "primary"), ("id", other.as_str()), reason];
    assert_eq!(redirect(&post(&emails, &primary).await), emails);
    let stored = harness.database.emails().list(user).await.expect("emails");
    let primary = stored
        .iter()
        .find(|email| email.is_primary)
        .expect("primary");
    assert_eq!(primary.id.to_string(), other);

    let handle = format!("/users/{user}/handle");
    let page = html(harness.visit(&dashboard, &handle).await).await;
    assert!(
        page.contains("Its old handle stays reserved for it"),
        "{page}"
    );
    let renamed = format!("renamed-{}", &user.to_string()[24..]);
    let done = post(&handle, &[("handle", renamed.as_str()), reason]).await;
    assert_eq!(redirect(&done), format!("/users/{user}"));
    let stored = harness
        .database
        .users()
        .find_by_id(user)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.handle.as_str(), renamed);
    // The handle rules refuse a rename, saying why, as they do the owner's.
    let refused = html(post(&handle, &[("handle", renamed.as_str()), reason]).await).await;
    assert!(refused.contains("This is already the account"), "{refused}");
}
