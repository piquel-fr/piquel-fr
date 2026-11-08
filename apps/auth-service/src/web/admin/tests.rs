//! The admin dashboard through auth's two listeners, as a browser uses them:
//! signing in by auth's handoff page, the dashboard's own confirmation, and the
//! admin listener's security layer.

use super::AdminApplication;
use crate::{
    AdminError, AdminService, AuthConfig, DashboardConfig, Reason,
    account::AccountService,
    admin::DashboardSignIn,
    assets::EmbeddedAssets,
    passkey::AdminProof,
    routes,
    security::{BrowserCookie, RequestContext},
    tests::{
        AUTH_ORIGIN, Browser, OWN_PAGE, Replicas, cookie, html, location, operator, parameter,
        policy, redirect, until_blocked,
    },
};
use axum::{
    Router,
    http::{StatusCode, header},
    response::Response,
};
use chrono::{DateTime, Utc};
use piquel_common::{
    AccountStatus, AuthenticationMethod, Handle, PictureId, UserId,
    events::{Actor, DomainEvent},
};
use piquel_repository::{
    Channel, Database, DatabaseError, DatabaseTransaction, EventFilter, NewDelivery,
    SigningKeyState,
};
use piquel_telemetry::{HttpTelemetry, Telemetry};
use piquel_ui::{HandoffQuery, LegacyConfirm};
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

    /// Follows `changed`, a change's redirect to the page showing what it made
    /// once, as `browser` with the sealed cookie the change set, and returns that
    /// page, which shows `made`. Its answer deletes the cookie, and `made` shows
    /// no more: not on the page again, as on a reload, nor with the cookie on
    /// another page, `elsewhere`.
    async fn shown_once(
        &self,
        browser: &Browser,
        changed: &Response,
        made: &str,
        elsewhere: &str,
    ) -> String {
        let page = redirect(changed).to_owned();
        let (sealed, _) = cookie(changed, BrowserCookie::DashboardReveal);
        let carrying = Browser {
            user_id: browser.user_id,
            session_id: browser.session_id,
            cookie: format!(
                "{}; {}={sealed}",
                browser.cookie,
                BrowserCookie::DashboardReveal
            ),
        };
        let shown = self.visit(&carrying, &page).await;
        assert_eq!(shown.status(), StatusCode::OK, "{page}");
        let (deleted, attributes) = cookie(&shown, BrowserCookie::DashboardReveal);
        assert_eq!(deleted, "");
        assert!(attributes.contains("Max-Age=0"), "{attributes}");
        let shown = html(shown).await;
        assert!(shown.contains(made), "{shown}");
        let reloaded = html(self.visit(browser, &page).await).await;
        assert!(!reloaded.contains(made), "{reloaded}");
        let misplaced = html(self.visit(&carrying, elsewhere).await).await;
        assert!(!misplaced.contains(made), "{misplaced}");
        shown
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
    /// state of its sign-in, the handoff it asked for, and auth's answer.
    async fn hand_off(&self, auth: &Browser, path: &str) -> (Browser, HandoffQuery, Response) {
        let started = self.visit(&Browser::signed_out(), path).await;
        assert_eq!(started.status(), StatusCode::SEE_OTHER);
        let handoff = location(&started);
        assert_eq!(handoff.path(), routes::page::ADMIN);
        assert_eq!(parameter(&handoff, "return_to"), path);
        // For the previous release's handoff page, which asks for a passkey only
        // then.
        assert_eq!(parameter(&handoff, "confirm"), "on");
        let (state, _) = cookie(&started, BrowserCookie::DashboardState);
        let query = HandoffQuery {
            state: state.to_owned(),
            return_to: path.to_owned(),
            confirm: LegacyConfirm,
        };
        let dashboard = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, state);
        (dashboard, query, self.to_auth(auth, &started).await)
    }

    /// Signs `auth`'s browser in to the dashboard, which opens its `path`, with a
    /// passkey proof of the handoff long past, so a change still needs a
    /// confirmation: the dashboard's browser, holding its session.
    async fn sign_in(&self, auth: &Browser, path: &str) -> Browser {
        let long_ago = Utc::now() - chrono::Duration::hours(1);
        self.confirmed(auth, path, long_ago).await
    }

    /// Signs `auth`'s browser in to the dashboard, which opens its `path`, with a
    /// passkey proof of the handoff at `proved_at`, as the handoff page asks for
    /// one: the dashboard's browser, holding its session.
    async fn confirmed(&self, auth: &Browser, path: &str, proved_at: DateTime<Utc>) -> Browser {
        let (dashboard, query, asked) = self.hand_off(auth, path).await;
        assert_eq!(asked.status(), StatusCode::OK, "asks for a passkey");
        let proof = AdminProof::unverified(auth.session_id, proved_at);
        let code_url = self
            .sign_in_service()
            .hand_off(&auth.owner(&self.database).await, &query, proof)
            .await
            .expect("handed off");
        self.redeem(&dashboard, &code_url, path).await
    }

    /// The dashboard's sign-in, as auth's handoff page runs it.
    fn sign_in_service(&self) -> DashboardSignIn {
        DashboardSignIn::new(
            self.database.clone(),
            AUTH_ORIGIN.parse().expect("auth origin"),
            DASHBOARD.parse().expect("dashboard origin"),
        )
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

/// A page that fails internally says so on the dashboard's page, which shows the
/// trace ID its `X-Trace-Id` header carries, for a report to quote.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_server_error_shows_its_trace_id() {
    let _capture = Telemetry::capture("info");
    let dashboard = DashboardConfig {
        listener: SocketAddr::from(([127, 0, 0, 1], 0)),
        origin: DASHBOARD.parse().expect("dashboard origin"),
    };
    let config = AuthConfig::test(&AUTH_ORIGIN.parse().expect("auth origin"));
    // Without the security layer, which gives every page its request context, every
    // page fails internally.
    let database = Replicas::database().await;
    let keys = config.test_keys(database.clone()).await;
    let passkeys = config
        .dashboard_passkeys(database.clone(), &keys)
        .expect("passkeys");
    let pages = AdminApplication::new(database, &config, &dashboard, passkeys)
        .expect("dashboard")
        .routes();
    let pages = HttpTelemetry::default().wrap(pages);
    let response = Browser::signed_out()
        .visit(&pages, &format!("{DASHBOARD}/users"))
        .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let trace_id = response.headers()[HttpTelemetry::TRACE_ID_HEADER]
        .to_str()
        .expect("trace ID")
        .to_owned();
    assert!(
        html(response)
            .await
            .contains(&format!(r#"<code id="reference">{trace_id}</code>"#)),
        "the page shows {trace_id}"
    );
}

/// An administrator's passkey session signs in to the dashboard through auth's
/// handoff page, which asks for a passkey every time, and the sign-in is recorded
/// as theirs. The code works once, only in the browser holding the state it was
/// bound to. Every page loads the dashboard's script alone, and posts only to
/// itself.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_asks_auth_for_a_passkey_once() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let (dashboard, query, asked) = harness.hand_off(&admin, "/users").await;
    assert_eq!(asked.status(), StatusCode::OK);
    assert!(
        html(asked)
            .await
            .contains(r#"data-passkey-assertion="/admin/proof""#),
        "asks for a passkey"
    );
    let proof = AdminProof::unverified(admin.session_id, Utc::now());
    let code_url = harness
        .sign_in_service()
        .hand_off(&admin.owner(&harness.database).await, &query, proof)
        .await
        .expect("handed off");
    let elsewhere = Browser::signed_out().with_cookie(BrowserCookie::DashboardState, "AAAA");
    let refused = elsewhere.visit(&harness.dashboard, code_url.as_str()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "another browser");
    let signed_in = harness.redeem(&dashboard, &code_url, "/users").await;
    let replayed = dashboard.visit(&harness.dashboard, code_url.as_str()).await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST, "once only");
    let recorded = harness
        .actor_of("dashboard_signed_in", |event| {
            *event
                == DomainEvent::DashboardSignedIn {
                    session_id: admin.session_id,
                }
        })
        .await;
    assert!(
        matches!(recorded, Some(Actor::User { user_id, .. }) if user_id == admin.user_id),
        "{recorded:?}"
    );

    let page = harness.visit(&signed_in, "/users").await;
    assert_eq!(page.status(), StatusCode::OK);
    let csp = policy(&page).to_owned();
    let handoff = format!("form-action 'self' {AUTH_ORIGIN}{};", routes::page::ADMIN);
    assert!(csp.contains(&handoff), "{csp}");
    let script = EmbeddedAssets::DASHBOARD_SCRIPT.path();
    assert!(
        csp.contains(&format!("script-src {DASHBOARD}{script};"))
            && csp.contains("connect-src 'self';")
            && csp.contains(&format!("img-src {AUTH_ORIGIN};")),
        "{csp}"
    );
    let handle = format!("@browser-{}", &admin.user_id.to_string()[24..]);
    assert!(
        html(page).await.contains(&handle),
        "the bar names the administrator"
    );
}

/// A dashboard session ends with its auth session, and with the account's
/// rights: granting them again revives no old cookie.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_dashboard_ends_with_the_auth_session_and_the_rights() {
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
    let ended = DomainEvent::DashboardSignedOut {
        session_id: revoked.session_id,
    };
    let recorded = harness
        .actor_of("dashboard_signed_out", |event| *event == ended)
        .await;
    assert!(matches!(recorded, Some(Actor::Cli { .. })), "{recorded:?}");
    harness.grant(revoked.user_id).await;
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(
        location(&page).path(),
        routes::page::ADMIN,
        "granting the rights again revives no session"
    );
}

/// A sign-in and a revocation of the account's rights at once: whichever holds
/// the rights first, no handoff or dashboard session outlives the revocation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_sign_in_racing_a_revocation_never_outlives_it() {
    let harness = Harness::new().await;
    // Another administrator, so the rights revoked are not the last.
    harness.admin().await;
    let service = AdminService::new(harness.database.clone(), true);
    let database = &harness.database;
    let in_use = |user_id| async move {
        (database.dashboard())
            .of_user(user_id, DashboardSignIn::idle_since())
            .await
            .expect("sessions")
    };

    // A redemption holding the rights writes its session before the revocation,
    // which waited for it, ends it.
    let admin = harness.admin().await;
    let mut redeeming = harness.database.begin().await.expect("transaction");
    let held = redeeming
        .administrators()
        .contains_for_share(admin.user_id)
        .await;
    assert!(held.expect("rights"));
    let cli = operator();
    let (revoked, ()) = tokio::join!(service.revoke_administrator(&cli, admin.user_id), async {
        until_blocked(&mut redeeming, 1).await;
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        (redeeming.dashboard())
            .insert_session(b"in flight", admin.session_id, Utc::now(), expires_at)
            .await
            .expect("session");
        redeeming.commit().await.expect("commit");
    });
    revoked.expect("revoke");
    assert!(
        in_use(admin.user_id).await.is_empty(),
        "ended by the revocation"
    );

    // A revocation holding the rights first refuses both the handoff and the
    // redemption waiting for it.
    let admin = harness.admin().await;
    let (dashboard, query, _) = harness.hand_off(&admin, "/users").await;
    let owner = admin.owner(&harness.database).await;
    let sign_in = harness.sign_in_service();
    let proof = || AdminProof::unverified(admin.session_id, Utc::now());
    let code_url = sign_in
        .hand_off(&owner, &query, proof())
        .await
        .expect("handed off");
    let mut revoking = harness.database.begin().await.expect("transaction");
    let revoked = revoking.administrators().revoke(admin.user_id).await;
    assert!(revoked.expect("revoke"));
    let (handed, redeemed, ()) = tokio::join!(
        sign_in.hand_off(&owner, &query, proof()),
        dashboard.visit(&harness.dashboard, code_url.as_str()),
        async {
            until_blocked(&mut revoking, 2).await;
            revoking.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(handed, Err(AdminError::NotAdministrator)),
        "{handed:?}"
    );
    assert_eq!(redeemed.status(), StatusCode::FORBIDDEN, "no access");
    harness.grant(admin.user_id).await;
    assert!(in_use(admin.user_id).await.is_empty(), "nothing revived");
}

/// A dashboard session times out once unused for half an hour: each request
/// keeps it going.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_idle_dashboard_session_expires() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.sign_in(&admin, "/users").await;
    let database = &harness.database;
    let idle = |minutes| async move {
        database
            .dashboard()
            .backdate_use(admin.session_id, chrono::Duration::minutes(minutes))
            .await
            .expect("backdate");
    };
    idle(29).await;
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(page.status(), StatusCode::OK, "still in use");
    idle(29).await;
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(page.status(), StatusCode::OK, "the last request counts");
    idle(31).await;
    let page = harness.visit(&dashboard, "/users").await;
    assert_eq!(location(&page).path(), routes::page::ADMIN, "timed out");
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

    let sign_in = harness.sign_in_service();
    let owner = admin.owner(&harness.database).await;
    let query = HandoffQuery {
        state: state.to_owned(),
        return_to: disable.clone(),
        confirm: LegacyConfirm,
    };
    let other = Browser::sign_in(&harness.database, admin.user_id).await;
    let elsewhere = AdminProof::unverified(other.session_id, Utc::now());
    let refused = sign_in.hand_off(&owner, &query, elsewhere).await;
    assert!(refused.is_err(), "a proof of another session");
    let proof = AdminProof::unverified(admin.session_id, Utc::now());
    let code_url = sign_in
        .hand_off(&owner, &query, proof)
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

/// The frame's dialog confirms the dashboard on its own page: it says how long
/// the confirmation lasts, nothing before it and five minutes after, and starts
/// the passkey ceremony for auth's RP ID, bound to the browser, as auth's own
/// pages do.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_dialog_confirms_on_the_page() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.sign_in(&admin, "/users").await;
    let page = html(harness.visit(&dashboard, "/users").await).await;
    assert!(
        page.contains(
            r#"data-confirmation-start="/confirm/start" data-confirmation-finish="/confirm/finish" data-confirmed-for="0" data-form-time="120""#
        ),
        "{page}"
    );
    let url = format!("{DASHBOARD}/confirm/start");
    let started = dashboard
        .submit(&harness.dashboard, &url, &[], OWN_PAGE)
        .await;
    assert_eq!(started.status(), StatusCode::OK);
    cookie(&started, BrowserCookie::Ceremony);
    let body: serde_json::Value = serde_json::from_str(&html(started).await).expect("JSON");
    assert!(body["ceremony_id"].is_string(), "{body}");
    let host = Url::parse(AUTH_ORIGIN).expect("auth origin");
    assert_eq!(
        body["public_key"]["publicKey"]["rpId"],
        host.host_str().expect("host")
    );

    let confirmed = harness.confirmed(&admin, "/users", Utc::now()).await;
    let page = html(harness.visit(&confirmed, "/users").await).await;
    assert!(!page.contains(r#"data-confirmed-for="0""#), "{page}");
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

/// An administrator removes the picture of a disabled account, which shows
/// nowhere while the account is disabled, with a reason, from its Profile page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_remove_a_disabled_accounts_picture() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    harness
        .database
        .pictures()
        .set(owner.user_id, PictureId::new(), b"picture")
        .await
        .expect("picture");
    harness
        .database
        .users()
        .set_status(owner.user_id, AccountStatus::Disabled)
        .await
        .expect("disable");
    let profile = format!("/users/{}/profile", owner.user_id);
    let dashboard = harness.confirmed(&admin, &profile, Utc::now()).await;
    let page = html(harness.visit(&dashboard, &profile).await).await;
    assert!(
        !page.contains(r#"<img class="avatar"#),
        "nothing to load: {page}"
    );
    assert!(page.contains("Remove picture"), "{page}");
    // Its changes on other pages ask for a passkey on this one first.
    let handle = format!("/users/{}/handle", owner.user_id);
    assert!(
        page.contains(&format!(
            r#"<a data-confirm-first="" class="button secondary small" href="{handle}""#
        )),
        "{page}"
    );

    let url = format!("{DASHBOARD}{profile}");
    let remove = [("action", "remove"), ("reason", "Impersonates someone")];
    let done = dashboard
        .submit(&harness.dashboard, &url, &remove, OWN_PAGE)
        .await;
    assert_eq!(redirect(&done), profile);
    let stored = harness.database.pictures().find(owner.user_id).await;
    assert!(stored.expect("read").is_none(), "removed");
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

/// A page inside a tab has the tab in its crumb, linking its page: an account's
/// reads "admin / users / handle", and the account's history "admin / users /
/// handle / security history", the handle linking the account. The tab's own
/// page names it once. The menus' names are lowercase; the account's are not.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_crumb_leads_through_the_tab() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let account = format!("/users/{}", owner.user_id);
    let dashboard = harness.sign_in(&admin, &account).await;
    let page = html(harness.visit(&dashboard, &account).await).await;
    let users = r#"<a href="/users">users</a>"#;
    assert!(page.contains(users), "{page}");
    // The menus' names are lowercase in the crumb; the account's own are not.
    assert!(page.contains(r#"<a href="/">admin</a>"#), "{page}");
    assert!(page.contains("<b>browser-"), "{page}");
    let page = html(harness.visit(&dashboard, "/users").await).await;
    assert!(!page.contains(users), "{page}");
    assert!(page.contains("<b>users</b>"), "{page}");
    let page = html(
        harness
            .visit(&dashboard, &format!("{account}/history"))
            .await,
    )
    .await;
    assert!(
        page.contains(&format!(r#"<a href="{account}">browser-"#)),
        "{page}"
    );
    assert!(page.contains("<b>security history</b>"), "{page}");
}

/// The audit page's form verifies as `audit verify` does and comes back to the
/// page, which then shows that verification, and the page says that pruning is
/// the database owner's, from the command line. The database is shared, so other
/// tests may have verified already: the isolated audit tests show that loading the
/// page verifies nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_audit_page_verifies_on_request_and_leaves_pruning_to_the_owner() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.sign_in(&admin, "/audit").await;
    let page = html(harness.visit(&dashboard, "/audit").await).await;
    assert!(page.contains("Audit history"), "{page}");
    assert!(page.contains("needs the database owner"), "{page}");
    let url = format!("{DASHBOARD}/audit");
    let verified = dashboard
        .submit(&harness.dashboard, &url, &[], OWN_PAGE)
        .await;
    assert_eq!(redirect(&verified), "/audit");
    let page = html(harness.visit(&dashboard, "/audit").await).await;
    assert!(page.contains("Events checked"), "{page}");
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
    let (_, _, refused) = harness.hand_off(&user, "/users").await;
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
    let (_, _, asked) = harness.hand_off(&social, "/users").await;
    let login = Url::parse(AUTH_ORIGIN)
        .and_then(|auth| auth.join(redirect(&asked)))
        .expect("sign-in URL");
    assert_eq!(login.path(), routes::page::LOGIN);
    assert_eq!(parameter(&login, "acr"), "phr");
    let back = parameter(&login, "return_to");
    assert!(back.starts_with(routes::page::ADMIN), "{back}");
    assert!(back.contains("confirm=on"), "kept for the previous release: {back}");
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
/// its own pages, and signing out ends the dashboard's session alone, recorded
/// as the administrator's.
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
    let ended = DomainEvent::DashboardSignedOut {
        session_id: admin.session_id,
    };
    let recorded = harness
        .actor_of("dashboard_signed_out", |event| *event == ended)
        .await;
    assert!(
        matches!(recorded, Some(Actor::User { user_id, .. }) if user_id == admin.user_id),
        "recorded as the administrator's: {recorded:?}"
    );
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
/// operations, each with a reason: renaming and removing a passkey, making
/// another address primary, and changing the display name from the account's
/// page. The pages offer nothing that adds a way in, and a change without a
/// reason, or only the owner's, is refused.
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

    let account = format!("/users/{user}");
    let name = format!("{account}/name");
    let page = html(harness.visit(&dashboard, &account).await).await;
    assert!(
        page.contains(&format!(r#"href="{name}">Change display name</a>"#)),
        "{page}"
    );
    // A refused name keeps the reason typed beside it.
    let page = html(post(&name, &[("display_name", " "), reason]).await).await;
    assert!(page.contains("Choose a display name"), "{page}");
    assert!(page.contains(r#"value="Asked by email""#), "{page}");
    let done = post(&name, &[("display_name", " Renamed by support "), reason]).await;
    assert_eq!(redirect(&done), format!("{account}/profile"));
    let stored = harness
        .database
        .users()
        .find_by_id(user)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.display_name, "Renamed by support");
}

/// An administrator's settings sidebar links the dashboard; nobody else's does.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_sidebars_link_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let other = Browser::new_account(&harness.database).await;
    let page = html(admin.visit(&harness.auth.a, "/settings").await).await;
    assert!(page.contains("Admin dashboard"), "{page}");
    assert!(page.contains(DASHBOARD), "{page}");
    let page = html(other.visit(&harness.auth.a, "/settings").await).await;
    assert!(!page.contains("Admin dashboard"), "{page}");
}

/// Granting rights starts from a search: the page lists the accounts matching a
/// handle, with a button for each that may be granted, and the button's form
/// makes the account an administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rights_are_granted_from_a_search() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let other = Browser::new_account(&harness.database).await;
    let dashboard = harness
        .confirmed(&admin, "/administrators/grant", Utc::now())
        .await;
    let empty = html(harness.visit(&dashboard, "/administrators/grant").await).await;
    assert!(empty.contains("Search for the account"), "{empty}");
    assert!(
        !empty.contains(r#"name="user_id""#),
        "nothing listed: {empty}"
    );
    let search = format!("/administrators/grant?q={}", other.user_id);
    let page = html(harness.visit(&dashboard, &search).await).await;
    assert!(
        page.contains(&format!(r#"name="user_id" value="{}""#, other.user_id)),
        "{page}"
    );
    let granted = dashboard
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}/administrators/grant"),
            &[("user_id", other.user_id.to_string().as_str())],
            OWN_PAGE,
        )
        .await;
    assert_eq!(redirect(&granted), "/administrators");
    let page = html(harness.visit(&dashboard, &search).await).await;
    assert!(page.contains(">Administrator<"), "{page}");
    assert!(
        !page.contains(r#"name="user_id""#),
        "granted already: {page}"
    );
}

/// An administrator schedules an account's deletion and restores it from the
/// dashboard, each with a reason; the account's page then offers Restore, not
/// Enable, and only the terminal purges at once.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletions_are_scheduled_and_restored_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let account = format!("/users/{}", owner.user_id);
    let delete = format!("{account}/delete");
    let dashboard = harness.confirmed(&admin, &delete, Utc::now()).await;
    // Confirmed, the dashboard shows the change's form on the account's page.
    let page = html(harness.visit(&dashboard, &account).await).await;
    assert!(page.contains(&format!(r#"action="{delete}""#)), "{page}");
    let page = html(harness.visit(&dashboard, &delete).await).await;
    assert!(
        page.contains("--immediately"),
        "the terminal purges: {page}"
    );
    let reason = [("reason", "Asked by email")];
    let post = async |path: &str| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, &reason, OWN_PAGE)
            .await
    };
    assert_eq!(redirect(&post(&delete).await), account);
    let status = async || {
        harness
            .database
            .users()
            .find_by_id(owner.user_id)
            .await
            .expect("lookup")
            .expect("account")
            .status
    };
    assert_eq!(status().await, AccountStatus::Deleting);

    let restore = format!("{account}/restore");
    let page = html(harness.visit(&dashboard, &account).await).await;
    assert!(page.contains(&format!(r#"action="{restore}""#)), "{page}");
    assert!(page.contains(">Restore<"), "{page}");
    assert!(!page.contains("/enable"), "{page}");
    assert_eq!(redirect(&post(&restore).await), account);
    assert_eq!(status().await, AccountStatus::Active);
}

/// A client's page lists its approved origins. An administrator
/// approves one of a trusted client's redirect origins from its page, and
/// removes it again; a malformed origin, or one that is not a redirect origin, is
/// refused beside the form. An untrusted client's page says why it has none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn related_origins_are_approved_and_removed_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    // Within auth's own domain, so it counts only as `piquel`, which every such
    // origin shares.
    let origin = format!("https://{}.auth.piquel.fr", UserId::new());
    let client = piquel_common::clients::ClientRegistration {
        trusted: true,
        ..crate::tests::registration(piquel_common::clients::ClientKind::Public, &origin)
    };
    crate::tests::register(&harness.database, &client)
        .await
        .expect("client");
    let untrusted = crate::tests::registration(piquel_common::clients::ClientKind::Public, &origin);
    crate::tests::register(&harness.database, &untrusted)
        .await
        .expect("untrusted client");
    let approve = format!("/clients/{}/origins/approve", client.id);
    let dashboard = harness.confirmed(&admin, &approve, Utc::now()).await;
    let client_page = format!("/clients/{}/overview", client.id);
    let page = html(harness.visit(&dashboard, &client_page).await).await;
    assert!(page.contains(&approve), "{page}");
    let other = html(
        harness
            .visit(&dashboard, &format!("/clients/{}/overview", untrusted.id))
            .await,
    )
    .await;
    assert!(other.contains("pages sign users in themselves."), "{other}");
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };

    let refused = html(post(&approve, &[("origin", "notes.example")]).await).await;
    assert!(refused.contains("role=\"alert\""), "{refused}");
    let elsewhere = format!("https://elsewhere-{}.auth.piquel.fr", UserId::new());
    let refused = html(post(&approve, &[("origin", &elsewhere)]).await).await;
    assert!(
        refused.contains("is not the origin of any redirect URI"),
        "{refused}"
    );
    assert!(
        refused.contains(&format!("value=\"{elsewhere}\"")),
        "the refused origin is kept: {refused}"
    );

    assert_eq!(
        redirect(&post(&approve, &[("origin", &origin)]).await),
        client_page
    );
    let page = html(harness.visit(&dashboard, &client_page).await).await;
    let remove = format!(
        "/clients/{}/origins/remove?origin={}",
        client.id,
        url::form_urlencoded::byte_serialize(origin.as_bytes()).collect::<String>()
    );
    assert!(page.contains(&remove), "listed: {page}");
    assert_eq!(redirect(&post(&remove, &[]).await), client_page);
    let listed = AdminService::new(harness.database.clone(), true)
        .list_related_origins(&operator())
        .await
        .expect("origins");
    assert!(
        !listed
            .iter()
            .any(|approved| approved.origin.as_str() == origin)
    );
}

/// The stored registration of client `id`.
async fn stored_client(database: &Database, id: &str) -> piquel_repository::StoredOidcClient {
    database
        .oidc()
        .find_client(id)
        .await
        .expect("lookup")
        .expect("client")
}

/// An administrator registers a confidential client with the settings only
/// operators choose, its secret shown once, on the page registering goes on
/// to; a refused registration keeps what was
/// typed. Its page then changes them, keeping the scopes beyond the standard ones,
/// suspends it, rotates its secret and deletes it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn clients_are_registered_changed_and_suspended_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.confirmed(&admin, "/clients/new", Utc::now()).await;
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };
    let id = format!("ops-{}", UserId::new());
    let registration = |redirect: &'static str| {
        [
            ("id", id.as_str()),
            ("display_name", "Ops app"),
            ("kind", "confidential"),
            ("redirect_uris", redirect),
            ("openid", "on"),
            ("other_scopes", "notes.read\r\n"),
            ("trusted", "on"),
            ("backchannel_logout_uri", "https://ops.example/backchannel"),
        ]
    };

    let refused = html(post("/clients/new", &registration("not a URI")).await).await;
    assert!(refused.contains("redirect_uris"), "{refused}");
    assert!(refused.contains(&format!(r#"value="{id}""#)), "{refused}");
    let created = post("/clients/new", &registration("https://ops.example/cb")).await;
    let client = format!("/clients/{id}");
    let page = format!("{client}/overview");
    assert_eq!(redirect(&created), page);
    let settings = format!("{client}/settings");
    // The secrets page shows what a rotation sealed for it, never this.
    harness
        .shown_once(&dashboard, &created, "pqcs_", &format!("{client}/secret"))
        .await;
    let stored = stored_client(&harness.database, &id).await;
    assert!(stored.trusted);
    assert_eq!(stored.owner_id, None);
    assert_eq!(stored.allowed_scopes, ["openid", "notes.read"]);
    assert_eq!(
        stored.backchannel_logout_uri.as_deref(),
        Some("https://ops.example/backchannel")
    );

    let list = html(harness.visit(&dashboard, "/clients").await).await;
    assert!(list.contains(&format!(r#"href="{page}""#)), "{list}");
    let form = html(harness.visit(&dashboard, &settings).await).await;
    assert!(form.contains(">notes.read</textarea>"), "{form}");
    let saved = post(
        &settings,
        &[
            ("display_name", "Ops app"),
            ("redirect_uris", "https://ops.example/cb"),
            ("openid", "on"),
            ("other_scopes", "notes.read"),
            ("backchannel_logout_uri", ""),
        ],
    )
    .await;
    assert_eq!(redirect(&saved), page);
    let stored = stored_client(&harness.database, &id).await;
    assert!(!stored.trusted, "an unchecked box clears the trust");
    assert_eq!(stored.backchannel_logout_uri, None);
    assert_eq!(stored.allowed_scopes, ["openid", "notes.read"]);

    assert_eq!(
        redirect(&post(&format!("{client}/suspend"), &[]).await),
        page
    );
    assert!(
        stored_client(&harness.database, &id)
            .await
            .suspended_at
            .is_some()
    );
    let shown = html(harness.visit(&dashboard, &page).await).await;
    assert!(shown.contains("Lift the suspension first."), "{shown}");
    let enable = html(post(&format!("{client}/enable"), &[]).await).await;
    assert!(enable.contains("lift the suspension"), "{enable}");

    let rotated = post(&format!("{client}/secret"), &[("action", "rotate")]).await;
    assert_eq!(redirect(&rotated), format!("{client}/secret"));
    harness
        .shown_once(&dashboard, &rotated, "pqcs_", &page)
        .await;
    let secrets = harness
        .database
        .oidc()
        .client_secrets(&id.parse().expect("client ID"))
        .await
        .expect("secrets");
    assert_eq!(secrets.len(), 2);
    assert!(secrets[0].expires_at.is_some(), "the first one is expiring");

    assert_eq!(
        redirect(&post(&format!("{client}/delete"), &[]).await),
        "/clients"
    );
    let shown = html(harness.visit(&dashboard, &page).await).await;
    assert!(shown.contains("Deleted on"), "{shown}");
    assert!(
        !shown.contains(&settings),
        "a deleted client changes no more: {shown}"
    );
}

/// A page whose change the registry could only refuse says so in place of its
/// form: a public client's secrets page, and every change page of a deleted
/// client. Registering a taken ID says it is taken.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_that_could_only_fail_refuse_at_once() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.confirmed(&admin, "/clients/new", Utc::now()).await;
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };
    let refused = async |path: &str, status: StatusCode, says: &str| {
        let response = harness.visit(&dashboard, path).await;
        assert_eq!(response.status(), status, "{path}");
        let page = html(response).await;
        assert!(page.contains(says), "{path}: {page}");
    };
    let id = format!("spa-{}", UserId::new());
    let registration = [
        ("id", id.as_str()),
        ("display_name", "Single-page app"),
        ("kind", "public"),
        ("redirect_uris", "https://spa.example/cb"),
        ("openid", "on"),
    ];
    let client = format!("/clients/{id}");
    let page = format!("{client}/overview");
    assert_eq!(redirect(&post("/clients/new", &registration).await), page);
    let taken = html(post("/clients/new", &registration).await).await;
    assert!(taken.contains("is taken"), "{taken}");

    let secret = format!("{client}/secret");
    refused(&secret, StatusCode::BAD_REQUEST, "is public").await;
    assert_eq!(
        redirect(&post(&format!("{client}/delete"), &[]).await),
        "/clients"
    );
    for change in [
        "origins/approve",
        "settings",
        "enable",
        "disable",
        "suspend",
        "unsuspend",
        "delete",
        "secret",
    ] {
        refused(
            &format!("{client}/{change}"),
            StatusCode::CONFLICT,
            "was deleted",
        )
        .await;
    }
}

/// An invitation's link shows once, on the page creating it goes back to.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_invitations_link_shows_once() {
    let origin = AUTH_ORIGIN.parse().expect("auth origin");
    let mut config = AuthConfig::test(&origin);
    config.passkey.invite_required = true;
    let harness = Harness::of(config).await;
    let admin = harness.admin().await;
    let dashboard = harness
        .confirmed(&admin, "/invitations/new", Utc::now())
        .await;
    let created = dashboard
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}/invitations/new"),
            &[("expires_in", "1d")],
            OWN_PAGE,
        )
        .await;
    assert_eq!(redirect(&created), "/invitations/new");
    let shown = harness
        .shown_once(&dashboard, &created, "invitation=", "/invitations")
        .await;
    assert!(
        shown.contains(&format!("{AUTH_ORIGIN}/register?")),
        "{shown}"
    );
}

/// A client whose ID is `new` has its overview like any other, apart from the
/// registration page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_client_named_new_has_its_overview() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.confirmed(&admin, "/clients/new", Utc::now()).await;
    // IDs are never reused, so an earlier run's client may hold it already.
    if harness
        .database
        .oidc()
        .find_client("new")
        .await
        .expect("lookup")
        .is_none()
    {
        let client = piquel_common::clients::ClientRegistration {
            id: "new".parse().expect("client ID"),
            ..crate::tests::registration(
                piquel_common::clients::ClientKind::Public,
                "https://new.example",
            )
        };
        crate::tests::register(&harness.database, &client)
            .await
            .expect("client");
    }

    let overview = html(harness.visit(&dashboard, "/clients/new/overview").await).await;
    assert!(
        overview.contains(r#"href="/clients/new/settings""#),
        "{overview}"
    );
    let registration = html(harness.visit(&dashboard, "/clients/new").await).await;
    assert!(registration.contains(r#"name="id""#), "{registration}");
}

/// A delivery no worker sends, which the dashboard's tests list, cancel and retry.
struct Unsent;

impl Channel for Unsent {
    const NAME: &'static str = "test_dashboard_unsent";
    type Recipient = ();
    type Payload = ();

    fn deliveries(
        _: &DomainEvent,
        _: Option<UserId>,
        _: Option<&piquel_repository::Notified>,
        _: &mut DatabaseTransaction<'_>,
    ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
        std::future::ready(Ok(vec![]))
    }
}

impl Harness {
    /// The actor of the newest event of `kind` that `found` picks, if any.
    async fn actor_of(&self, kind: &str, found: impl Fn(&DomainEvent) -> bool) -> Option<Actor> {
        let filter = EventFilter {
            kind: Some(kind.into()),
            ..EventFilter::default()
        };
        let events = self
            .database
            .events()
            .list(&filter, 100)
            .await
            .expect("events");
        events
            .into_iter()
            .find(|stored| stored.event.known().is_some_and(&found))
            .map(|stored| stored.actor)
    }
}

/// The deliveries page lists a channel's deliveries, filtered by status, each with
/// the change it may take: a pending one is cancelled from its row's dialog, and
/// then retried, each recorded as the administrator's: the dashboard acts as the
/// administrator signed in to it, never as the terminal.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deliveries_are_cancelled_and_retried_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let delivery = NewDelivery::<Unsent> {
        destination: "https://receiver.example".into(),
        recipient: (),
        payload: (),
        ordering_key: None,
    };
    let id = harness
        .database
        .deliveries()
        .insert(None, delivery)
        .await
        .expect("insert");
    let (cancel, retry) = (
        format!("/deliveries/{id}/cancel"),
        format!("/deliveries/{id}/retry"),
    );
    let dashboard = harness.confirmed(&admin, &cancel, Utc::now()).await;
    let listed = format!("/deliveries?status=&channel={}", Unsent::NAME);
    let page = html(harness.visit(&dashboard, &listed).await).await;
    assert!(page.contains(&format!(r#"action="{cancel}""#)), "{page}");
    assert!(
        !page.contains(&retry),
        "a pending delivery is not retried: {page}"
    );
    let failed = format!("/deliveries?status=failed&channel={}", Unsent::NAME);
    let page = html(harness.visit(&dashboard, &failed).await).await;
    assert!(page.contains("No delivery."), "{page}");
    let unknown = harness.visit(&dashboard, "/deliveries?status=lost").await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let post = async |path: &str| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, &[], OWN_PAGE)
            .await
    };
    assert_eq!(redirect(&post(&cancel).await), "/deliveries");
    let page = html(harness.visit(&dashboard, &listed).await).await;
    assert!(page.contains(&format!(r#"action="{retry}""#)), "{page}");
    assert!(page.contains("Cancelled"), "{page}");
    // Cancelled already, it is refused, saying why.
    let refused = html(post(&cancel).await).await;
    assert!(
        refused.contains("No pending or failed delivery"),
        "{refused}"
    );
    assert_eq!(redirect(&post(&retry).await), "/deliveries");
    for kind in ["delivery_cancelled", "delivery_retried"] {
        let actor = harness
            .actor_of(kind, |event| {
                matches!(
                    event,
                    DomainEvent::DeliveryCancelled { delivery_id }
                        | DomainEvent::DeliveryRetried { delivery_id } if *delivery_id == id
                )
            })
            .await;
        assert!(
            matches!(actor, Some(Actor::Admin { user_id, .. }) if user_id == admin.user_id),
            "{kind}: {actor:?}"
        );
    }
}

/// The signing keys page lists every key; an administrator publishes a next key
/// and revokes it. Importing stays at the terminal.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_keys_are_rotated_and_revoked_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let dashboard = harness.confirmed(&admin, "/keys/rotate", Utc::now()).await;
    let page = html(harness.visit(&dashboard, "/keys").await).await;
    assert!(page.contains("auth-service keys import"), "{page}");
    let post = async |path: &str| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, &[], OWN_PAGE)
            .await
    };
    assert_eq!(redirect(&post("/keys/rotate").await), "/keys");
    let next = harness
        .database
        .signing_keys()
        .list()
        .await
        .expect("keys")
        .into_iter()
        .find(|key| key.state == SigningKeyState::Next)
        .expect("a next key")
        .id;
    let revoke = format!("/keys/{next}/revoke");
    let page = html(harness.visit(&dashboard, "/keys").await).await;
    assert!(page.contains(&format!(r#"action="{revoke}""#)), "{page}");
    assert_eq!(redirect(&post(&revoke).await), "/keys");
    let keys = harness.database.signing_keys().list().await.expect("keys");
    assert!(keys.iter().all(|key| key.id != next), "revoked");
    let unknown = html(post(&revoke).await).await;
    assert!(unknown.contains("No signing key has ID"), "{unknown}");
}

/// The handles page manages every handle. An administrator reserves one for
/// someone, which the page lists and the rename form refuses until it allows a
/// reserved handle; the account holding it is then listed. Renamed again, its
/// old handle shows as released, and its row's release frees it; the
/// reservation's row removes it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn handles_are_reserved_given_released_and_unreserved() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let user = owner.user_id;
    let suffix = &user.to_string()[24..];
    let kept = format!("kept-{suffix}");
    let rename = format!("/users/{user}/handle");
    let dashboard = harness
        .confirmed(&admin, "/handles/reserve", Utc::now())
        .await;
    let post = async |path: &str, fields: &[(&str, &str)]| {
        let url = format!("{DASHBOARD}{path}");
        dashboard
            .submit(&harness.dashboard, &url, fields, OWN_PAGE)
            .await
    };
    let page = html(harness.visit(&dashboard, "/handles").await).await;
    assert!(page.contains("<code>support</code>"), "built in: {page}");

    let reserve = [("handle", kept.as_str()), ("reason", "For the new CTO")];
    assert_eq!(
        redirect(&post("/handles/reserve", &reserve).await),
        "/handles"
    );
    let refused = html(post("/handles/reserve", &reserve).await).await;
    assert!(
        refused.contains("This handle, or one that looks like it, is reserved already"),
        "{refused}"
    );
    let unreserve = format!("/handles/unreserve?handle={kept}");
    let page = html(harness.visit(&dashboard, "/handles").await).await;
    assert!(page.contains("For the new CTO"), "{page}");
    assert!(page.contains(&format!(r#"action="{unreserve}""#)), "{page}");

    let page = html(harness.visit(&dashboard, &rename).await).await;
    assert!(page.contains(r#"name="allow_reserved""#), "{page}");
    let give = [("handle", kept.as_str()), ("reason", "Reserved for them")];
    let refused = html(post(&rename, &give).await).await;
    assert!(refused.contains("role=\"alert\""), "{refused}");
    assert!(
        refused.contains(&format!(r#"value="{kept}""#)),
        "kept: {refused}"
    );
    let allowed = [give.as_slice(), &[("allow_reserved", "on")]].concat();
    assert_eq!(
        redirect(&post(&rename, &allowed).await),
        format!("/users/{user}/profile")
    );
    let page = html(harness.visit(&dashboard, "/handles").await).await;
    assert!(page.contains(&rename), "the holder is listed: {page}");

    let back = format!("back-{suffix}");
    let renamed = [("handle", back.as_str()), ("reason", "Moved on")];
    assert_eq!(
        redirect(&post(&rename, &renamed).await),
        format!("/users/{user}/profile")
    );
    let release = format!("/handles/release?handle={kept}");
    let page = html(harness.visit(&dashboard, "/handles").await).await;
    assert!(
        page.contains(&format!(r#"action="{release}""#)),
        "released: {page}"
    );
    assert_eq!(redirect(&post(&release, &[]).await), "/handles");
    let refused = html(post(&release, &[]).await).await;
    assert!(refused.contains("This handle is not released"), "{refused}");
    assert_eq!(redirect(&post(&unreserve, &[]).await), "/handles");
    let page = html(harness.visit(&dashboard, "/handles").await).await;
    assert!(
        !page.contains(&release) && !page.contains(&unreserve),
        "{page}"
    );
}

/// An administrator reads an account's inbox and security history as its owner
/// sees them, from the account's settings tabs, without a confirmation: each
/// notification's text in full, marking nothing read, and each change with who
/// made it and why, reporting nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_read_an_accounts_inbox_and_history() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let renamed =
        Handle::parse(&format!("told-{}", &owner.user_id.to_string()[24..])).expect("handle");
    AdminService::new(harness.database.clone(), true)
        .rename_handle(
            &operator(),
            owner.user_id,
            renamed,
            Reason::parse("Asked by email".into()).expect("reason"),
            false,
        )
        .await
        .expect("rename");
    let inbox = format!("/users/{}/notifications", owner.user_id);
    let history = format!("/users/{}/history", owner.user_id);
    let dashboard = harness.sign_in(&admin, &inbox).await;

    let page = html(harness.visit(&dashboard, &inbox).await).await;
    assert!(
        page.contains("Piquel support changed your handle"),
        "{page}"
    );
    assert!(
        page.contains("You now sign in with your new handle"),
        "{page}"
    );
    assert!(page.contains("Not read yet"), "{page}");
    assert!(
        !page.contains("Mark all as read"),
        "only the owner marks: {page}"
    );
    let unread = harness
        .database
        .notifications()
        .unread(owner.user_id)
        .await
        .expect("unread");
    assert_eq!(unread, 1);

    let page = html(harness.visit(&dashboard, &history).await).await;
    assert!(page.contains("as its owner sees it"), "{page}");
    assert!(page.contains("Handle changed"), "{page}");
    assert!(
        page.contains("By a Piquel operator: “Asked by email”"),
        "{page}"
    );
    assert!(
        !page.contains("This wasn’t me"),
        "only the owner reports: {page}"
    );
    let sign_in = format!("/users/{}/sign-in", owner.user_id);
    let dashboard = harness.confirmed(&admin, &sign_in, Utc::now()).await;
    let page = html(harness.visit(&dashboard, &sign_in).await).await;
    assert!(
        page.contains(&format!(r#"href="{history}""#)),
        "a tab: {page}"
    );
}

/// The draft form finds accounts to add, saving nothing; each result adds itself
/// to the list, which also takes pasted accounts. "Send" saves the draft and
/// sends it as saved once the dashboard is confirmed, and otherwise goes on to the
/// send page, which confirms first.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_draft_form_finds_accounts_and_sends_from_the_editor() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let handle = harness
        .database
        .users()
        .find_by_id(owner.user_id)
        .await
        .expect("lookup")
        .expect("owner")
        .handle
        .to_string();
    let unconfirmed = harness.sign_in(&admin, "/announcements/new").await;
    let new = format!("{DASHBOARD}/announcements/new");
    let text = [("subject", "Hello group"), ("body", "Short note.")];
    let post = async |browser: &Browser, fields: &[(&str, &str)]| {
        let fields: Vec<_> = text.iter().chain(fields).copied().collect();
        browser
            .submit(&harness.dashboard, &new, &fields, OWN_PAGE)
            .await
    };
    let found = html(post(&unconfirmed, &[("intent", "find"), ("find", &handle)]).await).await;
    assert!(
        found.contains(&format!(r#"name="add" value="{handle}""#)),
        "{found}"
    );
    let adding = [
        ("find", handle.as_str()),
        ("accounts", "pasted"),
        ("add", &handle),
    ];
    let added = html(post(&unconfirmed, &adding).await).await;
    assert!(
        added.contains(&format!("pasted\n{handle}</textarea>")),
        "{added}"
    );
    assert!(added.contains("Added"), "{added}");
    let listed = harness.database.announcements().list(100).await;
    assert!(
        !listed
            .expect("list")
            .iter()
            .any(|sent| sent.subject == "Hello group"),
        "finding and adding save nothing"
    );

    let to = [
        ("audience", "accounts"),
        ("accounts", handle.as_str()),
        ("intent", "send"),
    ];
    let unconfirmed_send = post(&unconfirmed, &to).await;
    let sending = redirect(&unconfirmed_send);
    assert!(sending.ends_with("/send?revision=1"), "{sending}");
    let confirmed = harness
        .confirmed(&admin, "/announcements/new", Utc::now())
        .await;
    let sent = post(&confirmed, &to).await;
    let shown = html(harness.visit(&confirmed, redirect(&sent)).await).await;
    assert!(shown.contains("Sent"), "{shown}");
}

/// An administrator drafts an announcement without a fresh confirmation, and
/// its page shows the email as it will be sent. Sending needs the dashboard's
/// confirmation; once sent, the draft's pages lead back to it, and its recipient
/// reads it in their inbox.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn announcements_are_drafted_then_sent_from_the_dashboard() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let owner = Browser::new_account(&harness.database).await;
    let unconfirmed = harness.sign_in(&admin, "/announcements/new").await;
    let recipient = owner.user_id.to_string();
    let drafted = unconfirmed
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}/announcements/new"),
            &[
                ("subject", "Planned maintenance"),
                (
                    "body",
                    "Sign-in pauses tonight.\r\n\r\nNothing else changes.",
                ),
                ("audience", "accounts"),
                ("accounts", &recipient),
            ],
            OWN_PAGE,
        )
        .await;
    let page = redirect(&drafted);
    assert!(page.starts_with("/announcements/"), "{page}");
    let draft = html(harness.visit(&unconfirmed, page).await).await;
    assert!(
        draft.contains("Hello,\n\nSign-in pauses tonight.\n\nNothing else changes."),
        "{draft}"
    );
    let send = format!("{page}/send?revision=1");
    assert!(draft.contains(&format!(r#"href="{send}""#)), "{draft}");
    let unconfirmed_send = harness.visit(&unconfirmed, &send).await;
    assert_eq!(location(&unconfirmed_send).path(), routes::page::ADMIN);

    // The draft changes after its page was read, which needs no confirmation.
    let edited = unconfirmed
        .submit(
            &harness.dashboard,
            &format!("{DASHBOARD}{page}/edit"),
            &[
                ("subject", "Planned maintenance"),
                (
                    "body",
                    "Sign-in pauses tomorrow.\r\n\r\nNothing else changes.",
                ),
                ("audience", "accounts"),
                ("accounts", &recipient),
            ],
            OWN_PAGE,
        )
        .await;
    assert_eq!(redirect(&edited), page);
    // The send page, reached through auth's confirmation, still posts the
    // revision the draft's page showed, so the change is refused, not sent.
    let confirmed = harness.confirmed(&admin, &send, Utc::now()).await;
    let confirming = html(harness.visit(&confirmed, &send).await).await;
    assert!(
        confirming.contains(r#"<input type="hidden" name="revision" value="1">"#),
        "the page posts the revision it was opened for: {confirming}"
    );
    let post = async |revision: &str| {
        confirmed
            .submit(
                &harness.dashboard,
                &format!("{DASHBOARD}{page}/send?revision={revision}"),
                &[("revision", revision)],
                OWN_PAGE,
            )
            .await
    };
    let changed = html(post("1").await).await;
    assert!(
        changed.contains("draft changed since you checked it"),
        "{changed}"
    );
    let checked = html(harness.visit(&confirmed, page).await).await;
    assert!(checked.contains("Sign-in pauses tomorrow."), "{checked}");
    assert!(checked.contains("/send?revision=2"), "{checked}");
    assert_eq!(redirect(&post("2").await), page);
    let shown = html(harness.visit(&confirmed, page).await).await;
    assert!(!shown.contains("/send?revision="), "{shown}");
    for sent in [format!("{page}/edit"), format!("{page}/send?revision=2")] {
        assert_eq!(redirect(&harness.visit(&confirmed, &sent).await), page);
    }
    // The recipient reads it in their inbox, its paragraphs kept.
    let inbox = html(
        owner
            .visit(&harness.auth.a, routes::page::settings::NOTIFICATIONS)
            .await,
    )
    .await;
    assert!(
        inbox.contains("<strong>Planned maintenance</strong>"),
        "{inbox}"
    );
    let mut notifications = harness.database.notifications();
    let received = notifications.list(owner.user_id, None, 10).await;
    let [received] = <[_; 1]>::try_from(received.expect("inbox")).expect("one notification");
    let item = routes::page::settings::NOTIFICATION.replace("{id}", &received.id.to_string());
    let shown = html(owner.visit(&harness.auth.a, &item).await).await;
    assert!(shown.contains("<p>Nothing else changes.</p>"), "{shown}");
}
